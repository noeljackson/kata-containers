// Copyright (c) 2019 Ant Financial
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::linux_abi::pcipath_from_dev_tree_path;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
#[cfg(target_arch = "s390x")]
use kata_types::device::DRIVER_BLK_CCW_TYPE;
use kata_types::device::{
    DRIVER_BLK_MMIO_TYPE, DRIVER_BLK_PCI_TYPE, DRIVER_NVDIMM_TYPE, DRIVER_SCSI_TYPE,
};
use kata_types::mount::{StorageDevice, KATA_BLOCK_VOLUME_CREATE_FS};
use nix::sys::stat::{major, minor};
use protocols::agent::Storage;
use tracing::instrument;

#[cfg(target_arch = "s390x")]
use crate::ccw;
#[cfg(target_arch = "s390x")]
use crate::device::block_device_handler::get_virtio_blk_ccw_device_name;
use crate::device::block_device_handler::{
    get_virtio_blk_mmio_device_name, get_virtio_blk_pci_device_name,
};
use crate::device::nvdimm_device_handler::wait_for_pmem_device;
use crate::device::scsi_device_handler::get_scsi_device_name;
use crate::storage::{
    common_storage_handler, new_device, set_ownership, StorageContext, StorageHandler,
};
use slog::Logger;
#[cfg(target_arch = "s390x")]
use std::str::FromStr;

const EPHEMERAL_ENCRYPTION_DRIVER_OPTION: &str = "encryption_key=ephemeral";
const CONFIDENTIAL_STORAGE_DRIVER_OPTION_PREFIX: &str = "io.codewire.storage.";
const CONFIDENTIAL_STORAGE_ENCRYPTION_KEY: &str = "io.codewire.storage.encryption";
const CONFIDENTIAL_STORAGE_SOURCE_KEY: &str = "io.codewire.storage.source";
const CONFIDENTIAL_STORAGE_KEY_URI_KEY: &str = "io.codewire.storage.key-uri";
const CONFIDENTIAL_STORAGE_FILESYSTEM_KEY: &str = "io.codewire.storage.filesystem";
const CONFIDENTIAL_STORAGE_GROW_KEY: &str = "io.codewire.storage.grow";
const CONFIDENTIAL_STORAGE_KEY_URI_PREFIX: &str = "kbs:///default/codewire-workspace-luks/";
const MKFS_EXT4: &str = "mkfs.ext4";
const BLOCK_EMPTYDIR_EXT4_MKFS_OPTS: [&str; 8] =
    ["-O", "^has_journal", "-m", "0", "-i", "163840", "-I", "128"];

#[derive(Debug, Eq, PartialEq)]
struct BlockStorageDriverOptions {
    has_ephemeral_encryption: bool,
    should_create_filesystem: bool,
    confidential_storage: Option<ConfidentialStorageDriverOptions>,
}

#[derive(Debug, Eq, PartialEq)]
struct ConfidentialStorageDriverOptions {
    key_uri: String,
}

fn get_device_number(dev_path: &str, metadata: Option<&fs::Metadata>) -> Result<String> {
    let dev_id = match metadata {
        Some(m) => m.rdev(),
        None => {
            let m =
                fs::metadata(dev_path).context(format!("get metadata on file {:?}", dev_path))?;
            m.rdev()
        }
    };
    Ok(format!("{}:{}", major(dev_id), minor(dev_id)))
}

async fn handle_block_storage(
    logger: &Logger,
    storage: &Storage,
    dev_num: &str,
) -> Result<Arc<dyn StorageDevice>> {
    let options = block_storage_driver_options(storage)?;

    if let Some(confidential_storage) = options.confidential_storage {
        crate::rpc::cdh_confidential_storage_mount(
            "block-device",
            dev_num,
            &storage.mount_point,
            &confidential_storage.key_uri,
        )
        .await?;
        set_ownership(logger, storage)?;
        new_device(storage.mount_point.clone())
    } else if options.has_ephemeral_encryption {
        let mkfs_opts = BLOCK_EMPTYDIR_EXT4_MKFS_OPTS.join(" ");
        crate::rpc::cdh_secure_mount(
            "block-device",
            dev_num,
            "luks2",
            &storage.mount_point,
            &mkfs_opts,
        )
        .await?;
        set_ownership(logger, storage)?;
        new_device(storage.mount_point.clone())
    } else {
        if options.should_create_filesystem {
            ensure_block_filesystem(logger, storage).await?;
        }
        let path = common_storage_handler(logger, storage)?;
        new_device(path)
    }
}

fn block_storage_driver_options(storage: &Storage) -> Result<BlockStorageDriverOptions> {
    block_storage_driver_options_with_claim(storage, crate::initdata::workspace_storage_key_id())
}

fn block_storage_driver_options_with_claim(
    storage: &Storage,
    initdata_key_id: Option<&str>,
) -> Result<BlockStorageDriverOptions> {
    let has_ephemeral_encryption = storage
        .driver_options
        .iter()
        .any(|opt| opt == EPHEMERAL_ENCRYPTION_DRIVER_OPTION);
    let should_create_filesystem = should_create_block_filesystem(storage);
    let confidential_storage = confidential_storage_driver_options(storage, initdata_key_id)?;

    if confidential_storage.is_some() && (has_ephemeral_encryption || should_create_filesystem) {
        return Err(anyhow!(
            "confidential storage cannot be combined with ephemeral encryption or host-requested filesystem creation"
        ));
    }

    if has_ephemeral_encryption && !should_create_filesystem {
        return Err(anyhow!(
            "{} requires {} for block storage",
            EPHEMERAL_ENCRYPTION_DRIVER_OPTION,
            KATA_BLOCK_VOLUME_CREATE_FS
        ));
    }

    Ok(BlockStorageDriverOptions {
        has_ephemeral_encryption,
        should_create_filesystem,
        confidential_storage,
    })
}

fn confidential_storage_driver_options(
    storage: &Storage,
    initdata_key_id: Option<&str>,
) -> Result<Option<ConfidentialStorageDriverOptions>> {
    let mut metadata = HashMap::new();
    for option in &storage.driver_options {
        if !option.starts_with(CONFIDENTIAL_STORAGE_DRIVER_OPTION_PREFIX) {
            continue;
        }
        let Some((key, value)) = option.split_once('=') else {
            return Err(anyhow!("malformed confidential storage driver option"));
        };
        if !matches!(
            key,
            CONFIDENTIAL_STORAGE_ENCRYPTION_KEY
                | CONFIDENTIAL_STORAGE_SOURCE_KEY
                | CONFIDENTIAL_STORAGE_KEY_URI_KEY
                | CONFIDENTIAL_STORAGE_FILESYSTEM_KEY
                | CONFIDENTIAL_STORAGE_GROW_KEY
        ) {
            return Err(anyhow!("unsupported confidential storage driver option"));
        }
        if metadata.insert(key, value).is_some() {
            return Err(anyhow!("duplicate confidential storage driver option"));
        }
    }

    if metadata.is_empty() {
        return Ok(None);
    }
    if metadata.len() != 5 {
        return Err(anyhow!("incomplete confidential storage driver options"));
    }
    if storage.fstype != "ext4"
        || metadata.get(CONFIDENTIAL_STORAGE_ENCRYPTION_KEY) != Some(&"luks2")
        || metadata.get(CONFIDENTIAL_STORAGE_SOURCE_KEY) != Some(&"auto")
        || metadata.get(CONFIDENTIAL_STORAGE_FILESYSTEM_KEY) != Some(&"ext4")
        || metadata.get(CONFIDENTIAL_STORAGE_GROW_KEY) != Some(&"true")
    {
        return Err(anyhow!("invalid confidential storage driver option value"));
    }

    let key_uri = metadata
        .get(CONFIDENTIAL_STORAGE_KEY_URI_KEY)
        .ok_or_else(|| anyhow!("missing confidential storage key URI"))?;
    let key_id = key_uri
        .strip_prefix(CONFIDENTIAL_STORAGE_KEY_URI_PREFIX)
        .ok_or_else(|| anyhow!("invalid confidential storage key URI"))?;
    if !crate::initdata::is_canonical_uuid(key_id) {
        return Err(anyhow!("invalid confidential storage key URI UUID"));
    }
    let measured_key_id = initdata_key_id
        .ok_or_else(|| anyhow!("missing measured confidential storage key ID claim"))?;
    if key_id != measured_key_id {
        return Err(anyhow!(
            "confidential storage key URI does not match measured init-data claim"
        ));
    }

    Ok(Some(ConfidentialStorageDriverOptions {
        key_uri: (*key_uri).to_string(),
    }))
}

fn should_create_block_filesystem(storage: &Storage) -> bool {
    storage
        .driver_options
        .iter()
        .any(|opt| opt == KATA_BLOCK_VOLUME_CREATE_FS)
}

async fn ensure_block_filesystem(logger: &Logger, storage: &Storage) -> Result<()> {
    match storage.fstype.as_str() {
        "ext4" => ensure_ext4_filesystem(logger, &storage.source).await,
        _ => Err(anyhow!(
            "creating filesystem {} for block storage is unsupported",
            storage.fstype
        )),
    }
}

async fn ensure_ext4_filesystem(logger: &Logger, source: &str) -> Result<()> {
    // This option is emitted for block emptyDir volumes, whose backing device
    // is ephemeral and freshly allocated for the pod.
    info!(logger, "creating ext4 filesystem"; "source" => source);
    let output = {
        // Keep the agent SIGCHLD handler from reaping this child before
        // tokio::process observes it.
        let _locker = rustjail::container::WAIT_PID_LOCKER.lock().await;
        // BLOCK_EMPTYDIR_EXT4_MKFS_OPTS mirrors CDH's EXT4_INTEGRITY_MKFS_OPTS
        // from confidential-data-hub/hub/src/storage/volume_type/blockdevice/mod.rs.
        // CDH's FsFormatter adds "-F" and its mapped device path separately in
        // confidential-data-hub/hub/src/storage/drivers/filesystem.rs; here the
        // agent invokes mkfs.ext4 directly, so add "-F" and source below.
        tokio::process::Command::new(MKFS_EXT4)
            .arg("-F")
            .args(BLOCK_EMPTYDIR_EXT4_MKFS_OPTS)
            .arg(source)
            .output()
            .await
            .with_context(|| format!("run {MKFS_EXT4} for {source}"))?
    };

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "{} failed for {}: status={}, stdout={}, stderr={}",
        MKFS_EXT4,
        source,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_with_driver_options(options: &[&str]) -> Storage {
        Storage {
            driver_options: options.iter().map(|opt| opt.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn block_storage_options_allow_normal_existing_storage() {
        let storage = storage_with_driver_options(&[]);

        let options = block_storage_driver_options(&storage).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: false,
                should_create_filesystem: false,
                confidential_storage: None,
            }
        );
    }

    #[test]
    fn block_storage_options_allow_plain_fresh_storage() {
        let storage = storage_with_driver_options(&[KATA_BLOCK_VOLUME_CREATE_FS]);

        let options = block_storage_driver_options(&storage).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: false,
                should_create_filesystem: true,
                confidential_storage: None,
            }
        );
    }

    #[test]
    fn block_storage_options_allow_encrypted_fresh_storage() {
        let storage = storage_with_driver_options(&[
            EPHEMERAL_ENCRYPTION_DRIVER_OPTION,
            KATA_BLOCK_VOLUME_CREATE_FS,
        ]);

        let options = block_storage_driver_options(&storage).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: true,
                should_create_filesystem: true,
                confidential_storage: None,
            }
        );
    }

    #[test]
    fn block_storage_options_reject_encryption_without_filesystem_creation() {
        let storage = storage_with_driver_options(&[EPHEMERAL_ENCRYPTION_DRIVER_OPTION]);

        let err = block_storage_driver_options(&storage).unwrap_err();

        assert!(err.to_string().contains(KATA_BLOCK_VOLUME_CREATE_FS));
    }

    const TEST_KEY_ID: &str = "01981234-5678-7abc-8def-0123456789ab";

    fn confidential_storage() -> Storage {
        Storage {
            fstype: "ext4".to_string(),
            driver_options: vec![
                format!("{CONFIDENTIAL_STORAGE_ENCRYPTION_KEY}=luks2"),
                format!("{CONFIDENTIAL_STORAGE_SOURCE_KEY}=auto"),
                format!(
                    "{CONFIDENTIAL_STORAGE_KEY_URI_KEY}={CONFIDENTIAL_STORAGE_KEY_URI_PREFIX}{TEST_KEY_ID}"
                ),
                format!("{CONFIDENTIAL_STORAGE_FILESYSTEM_KEY}=ext4"),
                format!("{CONFIDENTIAL_STORAGE_GROW_KEY}=true"),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn block_storage_options_allow_confidential_storage_bound_to_initdata() {
        let storage = confidential_storage();

        let options = block_storage_driver_options_with_claim(&storage, Some(TEST_KEY_ID)).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: false,
                should_create_filesystem: false,
                confidential_storage: Some(ConfidentialStorageDriverOptions {
                    key_uri: format!("{CONFIDENTIAL_STORAGE_KEY_URI_PREFIX}{TEST_KEY_ID}"),
                }),
            }
        );
    }

    #[test]
    fn block_storage_options_reject_confidential_storage_without_matching_initdata() {
        let storage = confidential_storage();

        assert!(block_storage_driver_options_with_claim(&storage, None).is_err());
        assert!(block_storage_driver_options_with_claim(
            &storage,
            Some("01989999-9999-7999-8999-999999999999")
        )
        .is_err());
    }

    #[test]
    fn block_storage_options_reject_invalid_confidential_contracts() {
        let mut cases = Vec::new();

        let mut missing = confidential_storage();
        missing.driver_options.pop();
        cases.push(missing);

        let mut unknown = confidential_storage();
        unknown
            .driver_options
            .push("io.codewire.storage.unexpected=value".to_string());
        cases.push(unknown);

        let mut duplicate = confidential_storage();
        duplicate
            .driver_options
            .push(format!("{CONFIDENTIAL_STORAGE_GROW_KEY}=true"));
        cases.push(duplicate);

        let mut wrong_value = confidential_storage();
        wrong_value.driver_options[1] = format!("{CONFIDENTIAL_STORAGE_SOURCE_KEY}=empty");
        cases.push(wrong_value);

        let mut wrong_filesystem = confidential_storage();
        wrong_filesystem.fstype = "xfs".to_string();
        cases.push(wrong_filesystem);

        let mut malformed_uri = confidential_storage();
        malformed_uri.driver_options[2] =
            format!("{CONFIDENTIAL_STORAGE_KEY_URI_KEY}=kbs:///default/other/{TEST_KEY_ID}");
        cases.push(malformed_uri);

        let mut mixed_ephemeral = confidential_storage();
        mixed_ephemeral
            .driver_options
            .push(EPHEMERAL_ENCRYPTION_DRIVER_OPTION.to_string());
        cases.push(mixed_ephemeral);

        for storage in cases {
            assert!(block_storage_driver_options_with_claim(&storage, Some(TEST_KEY_ID)).is_err());
        }
    }
}

#[derive(Debug)]
pub struct VirtioBlkMmioHandler {}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkMmioHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_MMIO_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        if !Path::new(&storage.source).exists() {
            get_virtio_blk_mmio_device_name(ctx.sandbox, &storage.source)
                .await
                .context("failed to get mmio device name")?;
        }
        let dev_num = get_device_number(&storage.source, None)?;
        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }
}

#[derive(Debug)]
pub struct VirtioBlkPciHandler {}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkPciHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_PCI_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        let dev_num: String;

        // If hot-plugged, get the device node path based on the PCI path
        // otherwise use the virt path provided in Storage Source
        if storage.source.starts_with("/dev") {
            let metadata = fs::metadata(&storage.source)
                .context(format!("get metadata on file {:?}", &storage.source))?;
            let mode = metadata.permissions().mode();
            if mode & libc::S_IFBLK == 0 {
                return Err(anyhow!("Invalid device {}", &storage.source));
            }
            dev_num = get_device_number(&storage.source, Some(&metadata))?;
        } else {
            let (root_complex, pcipath) = pcipath_from_dev_tree_path(&storage.source)?;
            let dev_path =
                get_virtio_blk_pci_device_name(ctx.sandbox, root_complex, &pcipath).await?;
            storage.source = dev_path;
            dev_num = get_device_number(&storage.source, None)?;
        }

        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }
}

#[cfg(target_arch = "s390x")]
#[derive(Debug)]
pub struct VirtioBlkCcwHandler {}

#[cfg(target_arch = "s390x")]
#[async_trait::async_trait]
impl StorageHandler for VirtioBlkCcwHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_CCW_TYPE]
    }

    #[cfg(target_arch = "s390x")]
    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        let ccw_device = ccw::Device::from_str(&storage.source)?;
        let dev_path = get_virtio_blk_ccw_device_name(ctx.sandbox, &ccw_device).await?;
        storage.source = dev_path;
        let dev_num = get_device_number(&storage.source, None)?;
        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }

    #[cfg(not(target_arch = "s390x"))]
    #[instrument]
    async fn create_device(
        &self,
        _storage: Storage,
        _ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Err(anyhow!("CCW is only supported on s390x"))
    }
}

#[derive(Debug)]
pub struct ScsiHandler {}

#[async_trait::async_trait]
impl StorageHandler for ScsiHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_SCSI_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        // Retrieve the device path from SCSI address.
        let dev_path = get_scsi_device_name(ctx.sandbox, &storage.source).await?;
        storage.source = dev_path.clone();

        let dev_num = get_device_number(&dev_path, None)?;
        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }
}

#[derive(Debug)]
pub struct PmemHandler {}

#[async_trait::async_trait]
impl StorageHandler for PmemHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_NVDIMM_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        // Retrieve the device for pmem storage
        wait_for_pmem_device(ctx.sandbox, &storage.source).await?;

        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }
}
