// Copyright (c) 2019 Ant Financial
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use kata_sys_util::mount::{create_mount_destination, parse_mount_options};
use kata_types::confidential_volume::KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT;
use kata_types::device::DRIVER_VIRTIOFS_TYPE;
use kata_types::mount::{StorageDevice, StorageHandlerManager, KATA_SHAREDFS_GUEST_PREMOUNT_TAG};
use nix::dir::Dir;
use nix::fcntl::AtFlags;
use nix::sys::stat::{fchmod, fstat, FileStat, Mode, SFlag};
use nix::unistd::{fchownat, Gid, Uid};
use pathrs::flags::{OpenFlags, ResolverFlags};
use pathrs::{Handle, Root};
use protocols::agent::Storage;
use protocols::types::FSGroupChangePolicy;
use slog::Logger;
use tokio::sync::Mutex;
use tracing::instrument;

use self::bind_watcher_handler::BindWatcherHandler;
use self::block_handler::{PmemHandler, ScsiHandler, VirtioBlkMmioHandler, VirtioBlkPciHandler};
pub use self::ephemeral_handler::update_ephemeral_mounts;
use self::ephemeral_handler::EphemeralHandler;
use self::fs_handler::{OverlayfsHandler, VirtioFsHandler};
use self::image_pull_handler::ImagePullHandler;
use self::local_handler::LocalHandler;
use self::multi_layer_erofs::{handle_multi_layer_erofs_group, is_multi_layer_storage};
use crate::mount::{baremount, is_mounted, remove_mounts};
use crate::sandbox::{Sandbox, StorageClaim, StorageReference, StorageReferenceProgress};

mod bind_watcher_handler;
mod block_handler;
mod ephemeral_handler;
mod fs_handler;
mod image_pull_handler;
mod local_handler;
pub mod multi_layer_erofs;

const RW_MASK: u32 = 0o660;
const RO_MASK: u32 = 0o440;
const EXEC_MASK: u32 = 0o110;
const MODE_SETGID: u32 = 0o2000;

#[derive(Clone, Copy, Debug)]
struct MountTopologyEntry<'a> {
    mount_point: &'a Path,
    fs_type: &'a str,
    mount_source: Option<&'a str>,
}

fn validate_confidential_mount_topology<'a>(
    mounts: impl IntoIterator<Item = MountTopologyEntry<'a>>,
) -> Result<()> {
    let plaintext_root = Path::new(KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT);
    let mut covering_mount_seen = false;

    for mount in mounts {
        if !plaintext_root.starts_with(mount.mount_point) {
            continue;
        }
        covering_mount_seen = true;
        let host_shared = matches!(mount.fs_type, "virtiofs" | "fuse.virtiofs" | "9p")
            || mount.mount_source == Some(KATA_SHAREDFS_GUEST_PREMOUNT_TAG);
        if host_shared {
            return Err(anyhow!(
                "confidential storage plaintext root is covered by host-shared mount {:?} (type {:?}, source {:?})",
                mount.mount_point,
                mount.fs_type,
                mount.mount_source
            ));
        }
    }

    if !covering_mount_seen {
        return Err(anyhow!(
            "confidential storage plaintext mount topology is ambiguous"
        ));
    }
    Ok(())
}

fn validate_current_confidential_mount_topology() -> Result<()> {
    let process =
        procfs::process::Process::myself().context("open the kata-agent mount namespace")?;
    let mounts = process
        .mountinfo()
        .context("read the kata-agent mount topology")?;
    validate_confidential_mount_topology(mounts.iter().map(|mount| MountTopologyEntry {
        mount_point: &mount.mount_point,
        fs_type: &mount.fs_type,
        mount_source: mount.mount_source.as_deref(),
    }))
}

fn storage_exports_confidential_mount_root(storage: &Storage) -> bool {
    let plaintext_root = Path::new(KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT);
    plaintext_root.starts_with(Path::new(&storage.mount_point))
        && (storage.driver == DRIVER_VIRTIOFS_TYPE
            || matches!(storage.fstype.as_str(), "virtiofs" | "fuse.virtiofs" | "9p")
            || storage.source == KATA_SHAREDFS_GUEST_PREMOUNT_TAG)
}

#[derive(Debug)]
pub struct StorageContext<'a> {
    cid: &'a Option<String>,
    logger: &'a Logger,
    sandbox: &'a Arc<Mutex<Sandbox>>,
}

/// An implementation of generic storage device.
#[derive(Default, Debug)]
pub struct StorageDeviceGeneric {
    path: Option<String>,
}

impl StorageDeviceGeneric {
    /// Create a new instance of `StorageStateCommon`.
    pub fn new(path: String) -> Self {
        StorageDeviceGeneric { path: Some(path) }
    }
}

impl StorageDevice for StorageDeviceGeneric {
    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    fn cleanup(&self) -> Result<()> {
        let path = match self.path() {
            None => return Ok(()),
            Some(v) => {
                if v.is_empty() {
                    // TODO: Bind watch, local, ephemeral volume has empty path, which will get leaked.
                    return Ok(());
                } else {
                    v
                }
            }
        };
        if !Path::new(path).exists() {
            return Ok(());
        }

        if matches!(is_mounted(path), Ok(true)) {
            let mounts = vec![path.to_string()];
            remove_mounts(&mounts)?;
        }
        if matches!(is_mounted(path), Ok(true)) {
            return Err(anyhow!("failed to umount mountpoint {}", path));
        }

        let p = Path::new(path);
        if p.is_dir() {
            let is_empty = p.read_dir()?.next().is_none();
            if !is_empty {
                return Err(anyhow!("directory is not empty when clean up storage"));
            }
            // "remove_dir" will fail if the mount point is backed by a read-only filesystem.
            // This is the case with the device mapper snapshotter, where we mount the block device
            // directly at the underlying sandbox path which was provided from the base RO kataShared
            // path from the host.
            let _ = fs::remove_dir(p);
        } else if !p.is_file() {
            // TODO: should we remove the file for bind mount?
            return Err(anyhow!(
                "storage path {} is neither directory nor file",
                path
            ));
        }

        Ok(())
    }
}

/// Trait object to handle storage device.
#[async_trait::async_trait]
pub trait StorageHandler: Send + Sync {
    /// Create a new storage device.
    async fn create_device(
        &self,
        storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>>;

    /// Return the driver types that the handler manages.
    fn driver_types(&self) -> &[&str];
}

#[rustfmt::skip]
lazy_static! {
    pub static ref STORAGE_HANDLERS: StorageHandlerManager<Arc<dyn StorageHandler>> = {
        let mut manager: StorageHandlerManager<Arc<dyn StorageHandler>> = StorageHandlerManager::new();
        let handlers: Vec<Arc<dyn StorageHandler>> = vec![
            Arc::new(VirtioBlkMmioHandler {}),
            Arc::new(VirtioBlkPciHandler {}),
            Arc::new(EphemeralHandler {}),
            Arc::new(LocalHandler {}),
            Arc::new(PmemHandler {}),
            Arc::new(OverlayfsHandler {}),
            Arc::new(ScsiHandler {}),
            Arc::new(VirtioFsHandler {}),
            Arc::new(BindWatcherHandler {}),
            #[cfg(target_arch = "s390x")]
            Arc::new(self::block_handler::VirtioBlkCcwHandler {}),
            Arc::new(ImagePullHandler {}),
            Arc::new(self::multi_layer_erofs::MultiLayerErofsHandler {}),
        ];

        for handler in handlers {
            manager.add_handler(handler.driver_types(), handler.clone()).unwrap();
        }

        manager
    };
}

/// Result of multi-layer storage handling
struct MultiLayerProcessResult {
    /// The primary device created
    device: Arc<dyn StorageDevice>,
    /// All mount points that were processed as part of this group
    processed_mount_points: Vec<String>,
    /// Temporary mount points (upper/lower) backing the overlay, needed for
    /// container-scoped cleanup via `container_mounts`.
    temp_mount_points: Vec<String>,
    /// dm-verity device paths that need to be destroyed during cleanup
    verity_devices: Vec<String>,
}

/// Handle multi-layer storage by creating the overlay device.
/// Returns None if the storage is not a multi-layer storage.
/// Returns Some(Ok(result)) if successfully processed.
/// Returns Some(Err(e)) if there was an error.
async fn handle_multi_layer_storage(
    logger: &Logger,
    storage: &Storage,
    storages: &[Storage],
    sandbox: &Arc<Mutex<Sandbox>>,
    cid: &Option<String>,
    processed_mount_points: &HashSet<String>,
) -> Result<Option<MultiLayerProcessResult>> {
    if !is_multi_layer_storage(storage) {
        return Ok(None);
    }

    // Skip if already processed as part of a previous multi-layer group
    if processed_mount_points.contains(&storage.mount_point) {
        return Ok(None);
    }

    info!(
        logger,
        "Processing multi-layer EROFS storage";
        "mount-point" => &storage.mount_point,
        "source" => &storage.source,
        "driver" => &storage.driver,
        "fstype" => &storage.fstype,
    );

    let group_mount_points = storages
        .iter()
        .filter(|storage| is_multi_layer_storage(storage))
        .fold(Vec::new(), |mut mount_points, storage| {
            if !mount_points.contains(&storage.mount_point) {
                mount_points.push(storage.mount_point.clone());
            }
            mount_points
        });
    let mut claims = Vec::with_capacity(group_mount_points.len());
    for mount_point in &group_mount_points {
        let shared = storages
            .iter()
            .find(|storage| storage.mount_point == *mount_point)
            .map_or(storage.shared, |storage| storage.shared);
        let claim = sandbox.lock().await.claim_storage_reference(
            cid.as_deref(),
            mount_point.clone(),
            shared,
        )?;
        claims.push((mount_point.clone(), claim));
    }

    let initializer_count = claims
        .iter()
        .filter(|(_, claim)| claim.is_initializer())
        .count();
    if initializer_count == 0 {
        let mut device = None;
        for (mount_point, claim) in claims {
            let ready = claim
                .wait_until_ready()
                .await
                .with_context(|| format!("wait for multi-layer sandbox storage {mount_point}"))?;
            if device.is_none() {
                device = Some(ready);
            }
        }
        return Ok(Some(MultiLayerProcessResult {
            device: device.ok_or_else(|| anyhow!("multi-layer storage group is empty"))?,
            processed_mount_points: group_mount_points,
            temp_mount_points: Vec::new(),
            verity_devices: Vec::new(),
        }));
    }
    if initializer_count != claims.len() {
        let error =
            anyhow!("multi-layer storage group has mixed initialized and uninitialized ownership");
        for (_, claim) in &claims {
            claim.fail_initialization(&error);
        }
        return Err(error);
    }

    let result = match handle_multi_layer_erofs_group(storage, storages, cid, sandbox, logger).await
    {
        Ok(result) => result,
        Err(error) => {
            for (_, claim) in &claims {
                claim.fail_initialization(&error);
            }
            return Err(error);
        }
    };

    if result.processed_mount_points != group_mount_points {
        let error =
            anyhow!("multi-layer storage group changed after lifecycle ownership was claimed");
        for (_, claim) in &claims {
            claim.fail_initialization(&error);
        }
        return Err(error);
    }

    // Create device for the mount point
    let device = match new_device(result.mount_point.clone()) {
        Ok(device) => device,
        Err(error) => {
            for (_, claim) in &claims {
                claim.fail_initialization(&error);
            }
            return Err(error);
        }
    };

    for (mount_point, claim) in &claims {
        update_storage_device(sandbox, mount_point, claim, device.clone(), logger).await?;
    }

    Ok(Some(MultiLayerProcessResult {
        device,
        processed_mount_points: result.processed_mount_points,
        temp_mount_points: result.temp_mount_points,
        verity_devices: result.verity_devices,
    }))
}

/// Update sandbox storage with the created device.
/// Handles cleanup on failure.
async fn update_storage_device(
    sandbox: &Arc<Mutex<Sandbox>>,
    mount_point: &str,
    claim: &StorageClaim,
    device: Arc<dyn StorageDevice>,
    logger: &Logger,
) -> Result<()> {
    let install_device = device.clone();
    if let Err(device) = claim.retain_initialization_cleanup_device(device) {
        if let Err(cleanup_error) = device.cleanup() {
            error!(logger, "failed to clean storage after losing initialization ownership"; "mount-point" => mount_point, "error" => ?cleanup_error);
        }
        return Err(anyhow!(
            "storage initialization ownership was lost before installing device: {}",
            mount_point
        ));
    }

    if let Err(device) =
        sandbox
            .lock()
            .await
            .update_sandbox_storage(mount_point, claim, install_device)
    {
        error!(logger, "failed to update device for storage"; "mount-point" => mount_point);
        let recovery = claim.fail_initialization_with_device(
            format!("failed to install initialized sandbox storage {mount_point}"),
            device,
        );
        if let Err(device) = recovery {
            if let Err(cleanup_error) = device.cleanup() {
                error!(logger, "failed to clean unowned initialized storage"; "mount-point" => mount_point, "error" => ?cleanup_error);
            }
        }
        return Err(anyhow!(
            "failed to update device for storage: {}",
            mount_point
        ));
    }
    Ok(())
}

// add_storages takes a list of storages passed by the caller, and perform the
// associated operations such as waiting for the device to show up, and mount
// it to a specific location, according to the type of handler chosen, and for
// each storage.
#[instrument]
pub async fn add_storages(
    logger: Logger,
    storages: Vec<Storage>,
    sandbox: &Arc<Mutex<Sandbox>>,
    cid: Option<String>,
) -> Result<Vec<String>> {
    // Reject malformed confidential requests as one pure preflight pass. This keeps a later
    // invalid entry from leaving an earlier volume mounted or activated.
    for storage in &storages {
        block_handler::validate_confidential_storage_contract(storage)?;
    }
    let requests_confidential_storage = storages
        .iter()
        .any(|storage| storage.confidential_storage.is_some());
    let requests_host_shared_plaintext_root =
        storages.iter().any(storage_exports_confidential_mount_root);
    sandbox.lock().await.admit_confidential_mount_topology(
        requests_confidential_storage,
        requests_host_shared_plaintext_root,
    )?;
    if requests_confidential_storage {
        validate_current_confidential_mount_topology()?;
    }

    sandbox
        .lock()
        .await
        .begin_storage_transaction(cid.as_deref())?;
    let result = add_storages_inner(logger, storages, sandbox, cid.clone()).await;
    if let Err(error) = result {
        let mut sandbox = sandbox.lock().await;
        if let Some(cid) = cid.as_ref() {
            // Mark ownership before the first rollback await. Cancellation must
            // leave a discoverable cleanup transaction, not a stranded ledger.
            sandbox.pending_storage_cleanup.insert(cid.clone());
        }
        let rollback = {
            let mut cleanup = StorageReferenceCleanup::take(&mut sandbox, cid.as_deref());
            match cleanup.run().await {
                Ok(()) => cleanup.finish(),
                Err(error) => Err(error),
            }
        };
        if rollback.is_ok() {
            if let Some(cid) = cid.as_ref() {
                sandbox.pending_storage_cleanup.remove(cid);
            }
        }
        return Err(error).context(format!("roll back added storages: {rollback:?}"));
    }

    result
}

async fn add_storages_inner(
    logger: Logger,
    storages: Vec<Storage>,
    sandbox: &Arc<Mutex<Sandbox>>,
    cid: Option<String>,
) -> Result<Vec<String>> {
    let mut mount_list = Vec::new();
    let mut processed_mount_points = HashSet::new();

    for storage in &storages {
        // Try multi-layer storage handling first
        if let Some(result) = handle_multi_layer_storage(
            &logger,
            storage,
            &storages,
            sandbox,
            &cid,
            &processed_mount_points,
        )
        .await?
        {
            // Register all processed mount points
            for mp in &result.processed_mount_points {
                processed_mount_points.insert(mp.clone());
            }

            // Add the primary mount point to the list first, followed by
            // the temporary backing mounts (upper, lower-*).  Cleanup
            // iterates in order, so the overlay target is unmounted before
            // the mounts it depends on.
            if let Some(path) = result.device.path() {
                if !path.is_empty() {
                    mount_list.push(path.to_string());
                }
            }
            mount_list.extend(result.temp_mount_points);
            mount_list.extend(result.verity_devices.clone());

            // Record verity devices for cleanup
            if let Some(ref cid) = cid {
                if !result.verity_devices.is_empty() {
                    let mut sandbox_guard = sandbox.lock().await;
                    sandbox_guard
                        .container_verity_devices
                        .entry(cid.clone())
                        .or_insert_with(Vec::new)
                        .extend(result.verity_devices.clone());
                }
            }

            continue;
        }

        // Skip if already processed as part of multi-layer group
        if processed_mount_points.contains(&storage.mount_point) {
            continue;
        }

        // Standard storage handling
        let path = storage.mount_point.clone();
        let claim = sandbox.lock().await.claim_storage_reference(
            cid.as_deref(),
            path.clone(),
            storage.shared,
        )?;
        if !claim.is_initializer() {
            let device = claim
                .wait_until_ready()
                .await
                .with_context(|| format!("wait for sandbox storage {path}"))?;
            if let Some(p) = device.path() {
                if !p.is_empty() {
                    mount_list.push(p.to_string());
                }
            }
            // The device already exists.
            continue;
        }

        // Create device using handler
        let device = if let Some(handler) = STORAGE_HANDLERS.handler(&storage.driver) {
            let logger =
                logger.new(o!("subsystem" => "storage", "storage-type" => storage.driver.clone()));
            let mut ctx = StorageContext {
                cid: &cid,
                logger: &logger,
                sandbox,
            };
            handler.create_device(storage.clone(), &mut ctx).await
        } else {
            Err(anyhow!(
                "Failed to find the storage handler {}",
                storage.driver
            ))
        };

        match device {
            Ok(device) => {
                update_storage_device(sandbox, &path, &claim, device.clone(), &logger).await?;
                if let Some(p) = device.path() {
                    if !p.is_empty() {
                        mount_list.push(p.to_string());
                    }
                }
            }
            Err(e) => {
                error!(logger, "failed to create device for storage"; "error" => ?e);
                claim.fail_initialization(&e);
                return Err(e);
            }
        }
    }

    Ok(mount_list)
}

/// Release storage references in mount-before-activation order.
///
/// The CDH handle remains recorded until deactivation succeeds, so a failed rollback can be
/// retried by normal container or sandbox cleanup.
#[cfg(test)]
pub(crate) async fn remove_storage_references(
    sandbox: &mut Sandbox,
    references: &mut [StorageReference],
) -> Result<()> {
    remove_storage_references_with(sandbox, references, &CdhVolumeDeactivator).await
}

#[async_trait::async_trait]
trait VolumeDeactivator: Send + Sync {
    async fn deactivate(&self, activation_id: &str) -> Result<()>;
}

struct CdhVolumeDeactivator;

#[async_trait::async_trait]
impl VolumeDeactivator for CdhVolumeDeactivator {
    async fn deactivate(&self, activation_id: &str) -> Result<()> {
        crate::confidential_data_hub::deactivate_volume(activation_id).await
    }
}

/// Owns an in-progress cleanup ledger and restores it synchronously unless
/// every reference completed. This also covers async cancellation and panic
/// unwinding, not just ordinary `Result` failures.
pub(crate) struct StorageReferenceCleanup<'a> {
    sandbox: &'a mut Sandbox,
    cid: Option<String>,
    references: Option<Vec<StorageReference>>,
}

impl<'a> StorageReferenceCleanup<'a> {
    pub(crate) fn take(sandbox: &'a mut Sandbox, cid: Option<&str>) -> Self {
        let references = sandbox.take_storage_references(cid);
        Self::from_references(sandbox, cid, references)
    }

    pub(crate) fn from_references(
        sandbox: &'a mut Sandbox,
        cid: Option<&str>,
        references: Vec<StorageReference>,
    ) -> Self {
        Self {
            sandbox,
            cid: cid.map(ToString::to_string),
            references: Some(references),
        }
    }

    pub(crate) async fn run(&mut self) -> Result<()> {
        self.run_with(&CdhVolumeDeactivator).await
    }

    async fn run_with<D: VolumeDeactivator>(&mut self, deactivator: &D) -> Result<()> {
        let Self {
            sandbox,
            references,
            ..
        } = self;
        remove_storage_references_with(
            sandbox,
            references
                .as_mut()
                .ok_or_else(|| anyhow!("storage cleanup transaction is already complete"))?,
            deactivator,
        )
        .await
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if self
            .references
            .as_ref()
            .ok_or_else(|| anyhow!("storage cleanup transaction is already complete"))?
            .iter()
            .any(|reference| reference.progress != StorageReferenceProgress::Complete)
        {
            return Err(anyhow!(
                "storage cleanup transaction still has incomplete references"
            ));
        }
        self.references = None;
        Ok(())
    }
}

impl Drop for StorageReferenceCleanup<'_> {
    fn drop(&mut self) {
        let Some(references) = self.references.take() else {
            return;
        };
        if let Err(error) = self
            .sandbox
            .restore_storage_references(self.cid.as_deref(), references)
        {
            error!(
                self.sandbox.logger,
                "storage cleanup ledger changed while cleanup owned it";
                "container-id" => self.cid.as_deref().unwrap_or("<sandbox>"),
                "error" => format!("{error:#}"),
            );
        }
    }
}

async fn remove_storage_references_with<D: VolumeDeactivator>(
    sandbox: &mut Sandbox,
    references: &mut [StorageReference],
    deactivator: &D,
) -> Result<()> {
    for reference in references {
        let mount_point = &reference.mount_point;

        if reference.progress == StorageReferenceProgress::ReferenceHeld {
            let removed = if sandbox.storages.contains_key(mount_point) {
                sandbox
                    .remove_sandbox_storage(mount_point)
                    .await
                    .with_context(|| format!("remove sandbox storage {mount_point}"))?
            } else {
                true
            };
            if !removed {
                reference.progress = StorageReferenceProgress::Complete;
                continue;
            }
            reference.progress = StorageReferenceProgress::StorageReleased;
        }

        if reference.progress == StorageReferenceProgress::StorageReleased {
            if let Some(activation) = sandbox
                .confidential_storage_activations
                .get(mount_point)
                .cloned()
            {
                let activation_id = activation.activation_id.as_deref().ok_or_else(|| {
                    anyhow!(
                        "confidential storage {mount_point} has an ambiguous activation in progress"
                    )
                })?;
                deactivator
                    .deactivate(activation_id)
                    .await
                    .with_context(|| format!("deactivate confidential storage {mount_point}"))?;
                sandbox.remove_confidential_storage_activation(mount_point, activation_id)?;
            }
            reference.progress = StorageReferenceProgress::ConfidentialDeactivated;
        }

        if reference.progress == StorageReferenceProgress::ConfidentialDeactivated
            && sandbox.ordinary_storage_devices.contains_key(mount_point)
        {
            // A failed storage handler can leave a mount behind without installing
            // its StorageDevice. Keep that ambiguous identity protected and make
            // the transaction retryable until the mount is conclusively gone.
            match is_mounted(mount_point) {
                Ok(false) => {
                    sandbox.ordinary_storage_devices.remove(mount_point);
                }
                Ok(true) => {
                    return Err(anyhow!(
                        "ordinary block storage remains mounted at {mount_point}"
                    ));
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("verify ordinary block storage cleanup at {mount_point}")
                    });
                }
            }
        }
        if reference.progress == StorageReferenceProgress::ConfidentialDeactivated {
            reference.progress = StorageReferenceProgress::Complete;
        }
    }

    Ok(())
}

pub(crate) fn new_device(path: String) -> Result<Arc<dyn StorageDevice>> {
    let device = StorageDeviceGeneric::new(path);
    Ok(Arc::new(device))
}

#[instrument]
pub(crate) fn common_storage_handler(logger: &Logger, storage: &Storage) -> Result<String> {
    mount_storage(logger, storage)?;
    set_ownership(logger, storage)?;
    Ok(storage.mount_point.clone())
}

// mount_storage performs the mount described by the storage structure.
#[instrument]
fn mount_storage(logger: &Logger, storage: &Storage) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "mount"));

    // There's a special mechanism to create mountpoint from a `sharedfs` instance before
    // starting the kata-agent. Check for such cases.
    if storage.source == KATA_SHAREDFS_GUEST_PREMOUNT_TAG && is_mounted(&storage.mount_point)? {
        warn!(
            logger,
            "{} already mounted on {}, ignoring...",
            KATA_SHAREDFS_GUEST_PREMOUNT_TAG,
            &storage.mount_point
        );
        return Ok(());
    }

    let (flags, options) = parse_mount_options(&storage.options)?;
    let mount_path = Path::new(&storage.mount_point);
    let src_path = Path::new(&storage.source);
    create_mount_destination(src_path, mount_path, "", &storage.fstype)
        .context("Could not create mountpoint")?;

    info!(logger, "mounting storage";
        "mount-source" => src_path.display(),
        "mount-destination" => mount_path.display(),
        "mount-fstype"  => storage.fstype.as_str(),
        "mount-options" => options.as_str(),
    );

    baremount(
        src_path,
        mount_path,
        storage.fstype.as_str(),
        flags,
        options.as_str(),
        &logger,
    )
}

#[instrument]
pub(crate) fn parse_options(option_list: &[String]) -> HashMap<String, String> {
    let mut options = HashMap::new();
    for opt in option_list {
        let fields: Vec<&str> = opt.split('=').collect();
        if fields.len() == 2 {
            options.insert(fields[0].to_string(), fields[1].to_string());
        }
    }
    options
}

#[instrument]
pub fn set_ownership(logger: &Logger, storage: &Storage) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "mount", "fn" => "set_ownership"));

    // If fsGroup is not set, skip performing ownership change
    if storage.fs_group.is_none() {
        return Ok(());
    }

    let fs_group = storage.fs_group();
    let read_only = storage.options.contains(&String::from("ro"));
    let mount_path = Path::new(&storage.mount_point);
    let (root, root_stat) = open_ownership_root(mount_path).inspect_err(|err| {
        error!(logger, "failed to securely open mount path";
            "mount-path" => mount_path.to_str(),
            "error" => err.to_string(),
        )
    })?;

    if fs_group.group_change_policy == FSGroupChangePolicy::OnRootMismatch.into()
        && root_stat.st_gid == fs_group.group_id
    {
        let mut mask = if read_only { RO_MASK } else { RW_MASK };
        mask |= EXEC_MASK;

        // With fsGroup change policy to OnRootMismatch, if the current
        // gid of the mount path root directory matches the desired gid
        // and the current permission of mount path root directory is correct,
        // then ownership change will be skipped.
        let current_mode = root_stat.st_mode;
        if (mask & current_mode == mask) && (current_mode & MODE_SETGID != 0) {
            info!(logger, "skipping ownership change for volume";
                "mount-path" => mount_path.to_str(),
                "fs-group" => fs_group.group_id.to_string(),
            );
            return Ok(());
        }
    }

    info!(logger, "performing recursive ownership change";
        "mount-path" => mount_path.to_str(),
        "fs-group" => fs_group.group_id.to_string(),
    );
    recursive_ownership_change_from_root(
        &root,
        Path::new("."),
        root_stat.st_dev,
        None,
        Some(Gid::from_raw(fs_group.group_id)),
        read_only,
    )
}

#[instrument]
#[cfg(test)]
pub fn recursive_ownership_change(
    path: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    read_only: bool,
) -> Result<()> {
    let (root, root_stat) =
        open_ownership_root(path).context("change ownership during recursive fsGroup ownership")?;
    recursive_ownership_change_from_root(
        &root,
        Path::new("."),
        root_stat.st_dev,
        uid,
        gid,
        read_only,
    )
    .context("change ownership during recursive fsGroup ownership")
}

fn open_ownership_root(path: &Path) -> Result<(Root, FileStat)> {
    let relative = path
        .strip_prefix("/")
        .context("fsGroup mount path must be absolute")?;
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    let system_root = Root::open("/")?.with_resolver_flags(ResolverFlags::NO_SYMLINKS);
    let handle = system_root
        .resolve(relative)
        .context("resolve fsGroup mount path without symlinks")?;
    let stat = fstat(&handle).context("inspect fsGroup mount root handle")?;
    if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR) {
        return Err(anyhow!("fsGroup mount path is not a directory"));
    }

    let mut root = Root::from_fd(OwnedFd::from(handle));
    root.set_resolver_flags(ResolverFlags::NO_SYMLINKS);
    Ok((root, stat))
}

fn resolve_ownership_entry(
    root: &Root,
    relative: &Path,
    root_device: libc::dev_t,
) -> Result<Option<(Handle, FileStat)>> {
    // Inspect the leaf without following it so symlinks are skipped. Resolve a
    // second time with NO_SYMLINKS before use so an intermediate or raced leaf
    // symlink cannot become an authority-bearing handle.
    let inspection = root
        .as_ref()
        .with_resolver_flags(ResolverFlags::empty())
        .resolve_nofollow(relative)
        .with_context(|| format!("inspect fsGroup entry {relative:?} without following leaf"))?;
    let inspection_stat = fstat(&inspection)
        .with_context(|| format!("inspect fsGroup entry metadata for {relative:?}"))?;
    if SFlag::from_bits_truncate(inspection_stat.st_mode).contains(SFlag::S_IFLNK) {
        return Ok(None);
    }

    let handle = root
        .resolve(relative)
        .with_context(|| format!("resolve fsGroup entry {relative:?} without symlinks"))?;
    let stat =
        fstat(&handle).with_context(|| format!("inspect secured fsGroup entry {relative:?}"))?;
    if stat.st_dev != root_device {
        return Ok(None);
    }

    Ok(Some((handle, stat)))
}

fn directory_entries(handle: &Handle, relative: &Path) -> Result<Vec<OsString>> {
    let directory = handle
        .reopen(OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY | OpenFlags::O_NOFOLLOW)
        .with_context(|| format!("open fsGroup directory handle for {relative:?}"))?;
    let owned_fd: OwnedFd = directory.into();
    let mut directory = Dir::from_fd(owned_fd)
        .with_context(|| format!("read fsGroup directory handle for {relative:?}"))?;
    let mut entries = Vec::new();
    for entry in directory.iter() {
        let entry = entry.with_context(|| format!("read child entry below {relative:?}"))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        entries.push(OsString::from_vec(name.to_vec()));
    }
    Ok(entries)
}

fn apply_ownership_to_handle(
    handle: &Handle,
    stat: &FileStat,
    uid: Option<Uid>,
    gid: Option<Gid>,
    read_only: bool,
) -> Result<()> {
    let mut mask = if read_only { RO_MASK } else { RW_MASK };
    let is_directory = SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR);
    if is_directory {
        mask |= EXEC_MASK;
        mask |= MODE_SETGID;
    }

    // Reopen the already-resolved inode before changing ownership. This makes
    // unsupported special files fail before any partial ownership mutation.
    let permission_handle = if gid.is_some() {
        Some(handle.reopen(if is_directory {
            OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY | OpenFlags::O_NOFOLLOW
        } else {
            OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK | OpenFlags::O_NOFOLLOW
        })?)
    } else {
        None
    };

    fchownat(handle, "", uid, gid, AtFlags::AT_EMPTY_PATH)
        .context("change ownership during recursive fsGroup ownership")?;

    if let Some(permission_handle) = permission_handle {
        let current =
            fstat(handle).context("inspect inode after recursive fsGroup ownership change")?;
        let target_mode = Mode::from_bits_truncate(current.st_mode | mask);
        fchmod(permission_handle, target_mode)
            .context("change permissions during recursive fsGroup ownership")?;
    }

    Ok(())
}

fn recursive_ownership_change_from_root(
    root: &Root,
    relative: &Path,
    root_device: libc::dev_t,
    uid: Option<Uid>,
    gid: Option<Gid>,
    read_only: bool,
) -> Result<()> {
    let Some((handle, stat)) = resolve_ownership_entry(root, relative, root_device)? else {
        return Ok(());
    };

    if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR) {
        let entries = directory_entries(&handle, relative)?;
        let expected_device = stat.st_dev;
        let expected_inode = stat.st_ino;
        drop(handle);

        for entry in entries {
            recursive_ownership_change_from_root(
                root,
                &relative.join(entry),
                root_device,
                uid,
                gid,
                read_only,
            )?;
        }

        // A directory renamed or replaced while its children were traversed
        // must not inherit authority from the stale handle.
        let Some((handle, current)) = resolve_ownership_entry(root, relative, root_device)? else {
            return Err(anyhow!(
                "fsGroup directory changed identity during traversal: {relative:?}"
            ));
        };
        if current.st_dev != expected_device || current.st_ino != expected_inode {
            return Err(anyhow!(
                "fsGroup directory changed identity during traversal: {relative:?}"
            ));
        }
        return apply_ownership_to_handle(&handle, &current, uid, gid, read_only);
    }

    apply_ownership_to_handle(&handle, &stat, uid, gid, read_only)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Error;
    use nix::mount::MsFlags;
    use protocols::agent::FSGroup;
    use std::fs::File;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::thread;
    use tempfile::{tempdir, Builder};
    use test_utils::{
        skip_if_not_root, skip_loop_by_user, skip_loop_if_not_root, skip_loop_if_root, TestUserType,
    };

    #[test]
    fn confidential_mount_topology_accepts_guest_only_ancestors() {
        let root = Path::new("/");
        let run = Path::new("/run");
        let unrelated_share = Path::new("/mnt/host-share");
        validate_confidential_mount_topology([
            MountTopologyEntry {
                mount_point: root,
                fs_type: "ext4",
                mount_source: Some("/dev/vda1"),
            },
            MountTopologyEntry {
                mount_point: run,
                fs_type: "tmpfs",
                mount_source: Some("tmpfs"),
            },
            MountTopologyEntry {
                mount_point: unrelated_share,
                fs_type: "virtiofs",
                mount_source: Some(KATA_SHAREDFS_GUEST_PREMOUNT_TAG),
            },
        ])
        .unwrap();
    }

    #[test]
    fn confidential_mount_topology_rejects_host_shared_ancestors() {
        for (mount_point, fs_type, mount_source) in [
            (
                "/run/kata-containers/shared",
                "virtiofs",
                Some(KATA_SHAREDFS_GUEST_PREMOUNT_TAG),
            ),
            (
                "/run/kata-containers/shared/containers",
                "fuse.virtiofs",
                Some("inline-share"),
            ),
            (
                KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT,
                "9p",
                Some("host-passthrough"),
            ),
            ("/run", "ext4", Some(KATA_SHAREDFS_GUEST_PREMOUNT_TAG)),
        ] {
            let error = validate_confidential_mount_topology([
                MountTopologyEntry {
                    mount_point: Path::new("/"),
                    fs_type: "ext4",
                    mount_source: Some("/dev/vda1"),
                },
                MountTopologyEntry {
                    mount_point: Path::new(mount_point),
                    fs_type,
                    mount_source,
                },
            ])
            .unwrap_err();
            assert!(error.to_string().contains("host-shared mount"));
        }
    }

    #[test]
    fn confidential_mount_topology_rejects_missing_ancestor_evidence() {
        let error = validate_confidential_mount_topology([MountTopologyEntry {
            mount_point: Path::new("/mnt/unrelated"),
            fs_type: "tmpfs",
            mount_source: Some("tmpfs"),
        }])
        .unwrap_err();
        assert!(error.to_string().contains("topology is ambiguous"));
    }

    #[test]
    fn classifies_only_host_shares_that_cover_the_plaintext_root() {
        for storage in [
            Storage {
                driver: DRIVER_VIRTIOFS_TYPE.to_string(),
                mount_point: "/run/kata-containers/shared/containers".to_string(),
                ..Default::default()
            },
            Storage {
                fstype: "9p".to_string(),
                mount_point: KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT.to_string(),
                ..Default::default()
            },
            Storage {
                source: KATA_SHAREDFS_GUEST_PREMOUNT_TAG.to_string(),
                mount_point: "/run".to_string(),
                ..Default::default()
            },
        ] {
            assert!(storage_exports_confidential_mount_root(&storage));
        }

        for storage in [
            Storage {
                fstype: "tmpfs".to_string(),
                mount_point: "/run".to_string(),
                ..Default::default()
            },
            Storage {
                driver: DRIVER_VIRTIOFS_TYPE.to_string(),
                mount_point: "/mnt/unrelated".to_string(),
                ..Default::default()
            },
            Storage {
                driver: DRIVER_VIRTIOFS_TYPE.to_string(),
                mount_point: format!("{KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT}/child"),
                ..Default::default()
            },
        ] {
            assert!(!storage_exports_confidential_mount_root(&storage));
        }
    }

    #[tokio::test]
    async fn confidential_and_host_shared_requests_fail_closed_in_either_order() {
        let logger = slog::Logger::root(slog::Discard, o!());

        let mut shared_first = Sandbox::new(&logger).unwrap();
        shared_first
            .admit_confidential_mount_topology(false, true)
            .unwrap();
        assert!(shared_first
            .admit_confidential_mount_topology(true, false)
            .is_err());

        let mut confidential_first = Sandbox::new(&logger).unwrap();
        confidential_first
            .admit_confidential_mount_topology(true, false)
            .unwrap();
        assert!(confidential_first
            .admit_confidential_mount_topology(false, true)
            .is_err());
    }

    fn add_ready_storage(
        sandbox: &mut Sandbox,
        mount_point: &str,
        device: Arc<dyn StorageDevice>,
    ) -> StorageClaim {
        let claim = sandbox.add_sandbox_storage(mount_point, false).unwrap();
        assert!(claim.is_initializer());
        assert!(sandbox
            .update_sandbox_storage(mount_point, &claim, device)
            .is_ok());
        claim
    }

    #[tokio::test]
    async fn storage_rollback_releases_every_reference() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let mut sandbox = Sandbox::new(&logger).unwrap();
        let mount_point = "/run/kata-containers/shared/containers/passthrough/rollback-test";
        add_ready_storage(
            &mut sandbox,
            mount_point,
            Arc::new(StorageDeviceGeneric::default()),
        );
        sandbox.add_sandbox_storage(mount_point, false).unwrap();

        let mut references = vec![
            StorageReference::new(mount_point.to_string()),
            StorageReference::new(mount_point.to_string()),
        ];
        remove_storage_references(&mut sandbox, &mut references)
            .await
            .unwrap();

        assert!(!sandbox.storages.contains_key(mount_point));
    }

    #[tokio::test]
    async fn multi_layer_reuser_observes_ready_storage_without_remounting() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        let mount_point = "/run/kata-containers/ready-multi-layer";
        let ready_path = "/run/kata-containers/ready-multi-layer-device";
        {
            let mut sandbox = sandbox.lock().await;
            let claim = sandbox.add_sandbox_storage(mount_point, false).unwrap();
            assert!(sandbox
                .update_sandbox_storage(
                    mount_point,
                    &claim,
                    Arc::new(StorageDeviceGeneric::new(ready_path.to_string())),
                )
                .is_ok());
            sandbox
                .begin_storage_transaction(Some("multi-layer-reuser"))
                .unwrap();
        }
        let storage = Storage {
            mount_point: mount_point.to_string(),
            options: vec!["X-kata.multi-layer=true".to_string()],
            ..Default::default()
        };
        let cid = Some("multi-layer-reuser".to_string());

        let result = handle_multi_layer_storage(
            &logger,
            &storage,
            std::slice::from_ref(&storage),
            &sandbox,
            &cid,
            &HashSet::new(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(result.device.path(), Some(ready_path));
        let sandbox = sandbox.lock().await;
        assert_eq!(
            sandbox.container_storage_references["multi-layer-reuser"][0].mount_point,
            mount_point
        );
        assert_eq!(sandbox.storages[mount_point].ref_count().await, 2);
    }

    #[tokio::test]
    async fn cancelled_device_install_keeps_a_cleanup_owner() {
        struct CountCleanup(Arc<AtomicU32>);

        impl StorageDevice for CountCleanup {
            fn path(&self) -> Option<&str> {
                None
            }

            fn cleanup(&self) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        let mount_point = "/run/kata-containers/cancelled-device-install";
        let claim = sandbox
            .lock()
            .await
            .add_sandbox_storage(mount_point, false)
            .unwrap();
        let attempts = Arc::new(AtomicU32::new(0));

        let lock_blocker = sandbox.lock().await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            update_storage_device(
                &sandbox,
                mount_point,
                &claim,
                Arc::new(CountCleanup(attempts.clone())),
                &logger,
            ),
        )
        .await
        .is_err());
        drop(lock_blocker);
        drop(claim);

        let mut sandbox = sandbox.lock().await;
        assert_eq!(
            sandbox.storages[mount_point].phase(),
            crate::sandbox::StorageLifecyclePhase::Failed
        );
        assert!(sandbox.remove_sandbox_storage(mount_point).await.unwrap());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn partial_cleanup_retry_does_not_release_a_completed_reference_twice() {
        struct FailsOnceDevice(Arc<AtomicU32>);

        impl StorageDevice for FailsOnceDevice {
            fn path(&self) -> Option<&str> {
                None
            }

            fn cleanup(&self) -> Result<()> {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(anyhow!("injected second-storage cleanup failure"));
                }
                Ok(())
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let mut sandbox = Sandbox::new(&logger).unwrap();
        let first = "/run/kata-containers/storage-cleanup-first";
        let second = "/run/kata-containers/storage-cleanup-second";
        let attempts = Arc::new(AtomicU32::new(0));

        add_ready_storage(
            &mut sandbox,
            first,
            Arc::new(StorageDeviceGeneric::default()),
        );
        sandbox.add_sandbox_storage(first, false).unwrap();
        add_ready_storage(
            &mut sandbox,
            second,
            Arc::new(FailsOnceDevice(attempts.clone())),
        );
        let mut references = vec![
            StorageReference::new(first.to_string()),
            StorageReference::new(second.to_string()),
        ];

        assert!(remove_storage_references(&mut sandbox, &mut references)
            .await
            .is_err());
        assert_eq!(references[0].progress, StorageReferenceProgress::Complete);
        assert_eq!(
            references[1].progress,
            StorageReferenceProgress::ReferenceHeld
        );
        assert_eq!(sandbox.storages[first].ref_count().await, 1);
        assert_eq!(
            sandbox.storages[second].phase(),
            crate::sandbox::StorageLifecyclePhase::Recoverable
        );

        remove_storage_references(&mut sandbox, &mut references)
            .await
            .unwrap();
        assert_eq!(sandbox.storages[first].ref_count().await, 1);
        assert!(!sandbox.storages.contains_key(second));
        assert!(references
            .iter()
            .all(|reference| reference.progress == StorageReferenceProgress::Complete));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deactivation_failure_resumes_after_reference_release() {
        struct FailsOnceDeactivator(Arc<AtomicU32>);

        #[async_trait::async_trait]
        impl VolumeDeactivator for FailsOnceDeactivator {
            async fn deactivate(&self, _activation_id: &str) -> Result<()> {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(anyhow!("injected deactivation failure"));
                }
                Ok(())
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let mut sandbox = Sandbox::new(&logger).unwrap();
        let mount_point = "/run/kata-containers/deactivation-retry";
        let mapper = crate::sandbox::BlockDeviceIdentity::new(253, 17).unwrap();
        let claim = sandbox.add_sandbox_storage(mount_point, false).unwrap();
        sandbox.retain_failed_storage_device(
            mount_point,
            "injected post-activation mount failure",
            Arc::new(StorageDeviceGeneric::default()),
        );
        assert_eq!(
            claim.phase(),
            crate::sandbox::StorageLifecyclePhase::Recoverable
        );
        sandbox
            .register_confidential_storage_activation(
                mount_point,
                "activation-retry".to_string(),
                crate::sandbox::BlockDeviceIdentity::new(8, 17).unwrap(),
                mapper,
                &HashSet::from([mapper]),
            )
            .unwrap();
        let attempts = Arc::new(AtomicU32::new(0));
        let deactivator = FailsOnceDeactivator(attempts.clone());
        let mut references = vec![StorageReference::new(mount_point.to_string())];

        assert!(
            remove_storage_references_with(&mut sandbox, &mut references, &deactivator,)
                .await
                .is_err()
        );
        assert_eq!(
            references[0].progress,
            StorageReferenceProgress::StorageReleased
        );
        assert!(!sandbox.storages.contains_key(mount_point));
        assert!(sandbox
            .confidential_storage_activations
            .contains_key(mount_point));

        remove_storage_references_with(&mut sandbox, &mut references, &deactivator)
            .await
            .unwrap();
        assert_eq!(references[0].progress, StorageReferenceProgress::Complete);
        assert!(!sandbox
            .confidential_storage_activations
            .contains_key(mount_point));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ambiguous_activation_fails_closed_without_dropping_ownership() {
        struct UnexpectedDeactivator;

        #[async_trait::async_trait]
        impl VolumeDeactivator for UnexpectedDeactivator {
            async fn deactivate(&self, _activation_id: &str) -> Result<()> {
                panic!("an activation without an ID must not be deactivated by guesswork");
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let mut sandbox = Sandbox::new(&logger).unwrap();
        let mount_point = "/run/kata-containers/ambiguous-activation";
        let claim = sandbox.add_sandbox_storage(mount_point, false).unwrap();
        claim.fail_initialization(&anyhow!("injected activation transport failure"));
        sandbox
            .reserve_confidential_storage_activation(
                mount_point,
                crate::sandbox::BlockDeviceIdentity::new(8, 18).unwrap(),
                &HashSet::new(),
            )
            .unwrap();
        let mut references = vec![StorageReference::new(mount_point.to_string())];

        for _ in 0..2 {
            let error = remove_storage_references_with(
                &mut sandbox,
                &mut references,
                &UnexpectedDeactivator,
            )
            .await
            .unwrap_err();
            assert!(format!("{error:#}").contains("ambiguous activation in progress"));
            assert_eq!(
                references[0].progress,
                StorageReferenceProgress::StorageReleased
            );
            assert!(!sandbox.storages.contains_key(mount_point));
            assert!(sandbox
                .confidential_storage_activations
                .contains_key(mount_point));
        }
    }

    #[tokio::test]
    async fn cancelled_cleanup_restores_progress_before_releasing_ownership() {
        struct PendingDeactivator;
        struct SuccessfulDeactivator;

        #[async_trait::async_trait]
        impl VolumeDeactivator for PendingDeactivator {
            async fn deactivate(&self, _activation_id: &str) -> Result<()> {
                std::future::pending().await
            }
        }

        #[async_trait::async_trait]
        impl VolumeDeactivator for SuccessfulDeactivator {
            async fn deactivate(&self, _activation_id: &str) -> Result<()> {
                Ok(())
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let mut sandbox = Sandbox::new(&logger).unwrap();
        let cid = "cancelled-cleanup";
        let mount_point = "/run/kata-containers/cancelled-cleanup";
        sandbox.begin_storage_transaction(Some(cid)).unwrap();
        let claim = sandbox
            .claim_storage_reference(Some(cid), mount_point.to_string(), false)
            .unwrap();
        assert!(sandbox
            .update_sandbox_storage(
                mount_point,
                &claim,
                Arc::new(StorageDeviceGeneric::default()),
            )
            .is_ok());
        let mapper = crate::sandbox::BlockDeviceIdentity::new(253, 19).unwrap();
        sandbox
            .register_confidential_storage_activation(
                mount_point,
                "activation-cancelled".to_string(),
                crate::sandbox::BlockDeviceIdentity::new(8, 19).unwrap(),
                mapper,
                &HashSet::from([mapper]),
            )
            .unwrap();

        {
            let mut cleanup = StorageReferenceCleanup::take(&mut sandbox, Some(cid));
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(10),
                cleanup.run_with(&PendingDeactivator),
            )
            .await
            .is_err());
        }

        assert_eq!(
            sandbox.container_storage_references[cid][0].progress,
            StorageReferenceProgress::StorageReleased
        );
        assert!(!sandbox.storages.contains_key(mount_point));
        assert!(sandbox
            .confidential_storage_activations
            .contains_key(mount_point));

        {
            let mut cleanup = StorageReferenceCleanup::take(&mut sandbox, Some(cid));
            cleanup.run_with(&SuccessfulDeactivator).await.unwrap();
            cleanup.finish().unwrap();
        }
        assert!(!sandbox.container_storage_references.contains_key(cid));
        assert!(!sandbox
            .confidential_storage_activations
            .contains_key(mount_point));
    }

    #[tokio::test]
    async fn storage_cleanup_failure_keeps_activation_for_ordered_retry() {
        struct FailingDevice(Arc<AtomicU32>);

        impl StorageDevice for FailingDevice {
            fn path(&self) -> Option<&str> {
                None
            }

            fn cleanup(&self) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(anyhow!("injected cleanup failure"))
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let mut sandbox = Sandbox::new(&logger).unwrap();
        let mount_point = "/run/kata-containers/shared/containers/passthrough/ordered-test";
        let attempts = Arc::new(AtomicU32::new(0));
        add_ready_storage(
            &mut sandbox,
            mount_point,
            Arc::new(FailingDevice(attempts.clone())),
        );
        sandbox
            .register_confidential_storage_activation(
                mount_point,
                "activation-1".to_string(),
                crate::sandbox::BlockDeviceIdentity::new(8, 1).unwrap(),
                crate::sandbox::BlockDeviceIdentity::new(253, 1).unwrap(),
                &HashSet::from([crate::sandbox::BlockDeviceIdentity::new(253, 1).unwrap()]),
            )
            .unwrap();

        let mut references = vec![StorageReference::new(mount_point.to_string())];
        assert!(remove_storage_references(&mut sandbox, &mut references)
            .await
            .is_err());

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(sandbox.storages.contains_key(mount_point));
        assert_eq!(
            sandbox
                .confidential_storage_activations
                .get(mount_point)
                .and_then(|activation| activation.activation_id.as_deref()),
            Some("activation-1")
        );
    }

    #[tokio::test]
    async fn ordinary_storage_identity_is_removed_only_after_mount_is_gone() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let identity = crate::sandbox::BlockDeviceIdentity::new(8, 1).unwrap();

        let mut cleaned = Sandbox::new(&logger).unwrap();
        let cleaned_path = "/run/kata-containers/nonexistent-ordinary-storage-test";
        add_ready_storage(
            &mut cleaned,
            cleaned_path,
            Arc::new(StorageDeviceGeneric::default()),
        );
        cleaned
            .register_ordinary_storage_device(cleaned_path, identity, &HashSet::new())
            .unwrap();
        let mut references = vec![StorageReference::new(cleaned_path.to_string())];
        remove_storage_references(&mut cleaned, &mut references)
            .await
            .unwrap();
        assert!(!cleaned.ordinary_storage_devices.contains_key(cleaned_path));

        let mut mounted = Sandbox::new(&logger).unwrap();
        let mounted_path = "/proc";
        add_ready_storage(
            &mut mounted,
            mounted_path,
            Arc::new(StorageDeviceGeneric::default()),
        );
        mounted
            .register_ordinary_storage_device(mounted_path, identity, &HashSet::new())
            .unwrap();
        let mut references = vec![StorageReference::new(mounted_path.to_string())];
        assert!(remove_storage_references(&mut mounted, &mut references)
            .await
            .is_err());
        assert!(mounted.ordinary_storage_devices.contains_key(mounted_path));
    }

    #[test]
    fn test_mount_storage() {
        #[derive(Debug)]
        struct TestData<'a> {
            test_user: TestUserType,
            storage: Storage,
            error_contains: &'a str,

            make_source_dir: bool,
            make_mount_dir: bool,
            deny_mount_permission: bool,
        }

        impl Default for TestData<'_> {
            fn default() -> Self {
                TestData {
                    test_user: TestUserType::Any,
                    storage: Storage {
                        mount_point: "mnt".to_string(),
                        source: "src".to_string(),
                        fstype: "tmpfs".to_string(),
                        ..Default::default()
                    },
                    make_source_dir: true,
                    make_mount_dir: false,
                    deny_mount_permission: false,
                    error_contains: "",
                }
            }
        }

        let tests = &[
            TestData {
                test_user: TestUserType::NonRootOnly,
                error_contains: "EPERM: Operation not permitted",
                ..Default::default()
            },
            TestData {
                test_user: TestUserType::RootOnly,
                ..Default::default()
            },
            TestData {
                storage: Storage {
                    mount_point: "mnt".to_string(),
                    source: "src".to_string(),
                    fstype: "bind".to_string(),
                    ..Default::default()
                },
                make_source_dir: false,
                make_mount_dir: true,
                error_contains: "Could not create mountpoint",
                ..Default::default()
            },
            TestData {
                test_user: TestUserType::NonRootOnly,
                deny_mount_permission: true,
                error_contains: "Could not create mountpoint",
                ..Default::default()
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            skip_loop_by_user!(msg, d.test_user);

            let drain = slog::Discard;
            let logger = slog::Logger::root(drain, o!());

            let tempdir = tempdir().unwrap();

            let source = tempdir.path().join(&d.storage.source);
            let mount_point = tempdir.path().join(&d.storage.mount_point);

            let storage = Storage {
                source: source.to_str().unwrap().to_string(),
                mount_point: mount_point.to_str().unwrap().to_string(),
                ..d.storage.clone()
            };

            if d.make_source_dir {
                fs::create_dir_all(&storage.source).unwrap();
            }
            if d.make_mount_dir {
                fs::create_dir_all(&storage.mount_point).unwrap();
            }

            if d.deny_mount_permission {
                fs::set_permissions(
                    mount_point.parent().unwrap(),
                    fs::Permissions::from_mode(0o000),
                )
                .unwrap();
            }

            let result = mount_storage(&logger, &storage);

            // restore permissions so tempdir can be cleaned up
            if d.deny_mount_permission {
                fs::set_permissions(
                    mount_point.parent().unwrap(),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }

            if result.is_ok() {
                nix::mount::umount(&mount_point).unwrap();
            }

            let msg = format!("{msg}: result: {result:?}");
            if d.error_contains.is_empty() {
                assert!(result.is_ok(), "{}", msg);
            } else {
                assert!(result.is_err(), "{}", msg);
                let error_msg = format!("{}", result.unwrap_err());
                assert!(error_msg.contains(d.error_contains), "{}", msg);
            }
        }
    }

    #[test]
    fn test_set_ownership() {
        skip_if_not_root!();

        let logger = slog::Logger::root(slog::Discard, o!());

        #[derive(Debug)]
        struct TestData<'a> {
            mount_path: &'a str,
            fs_group: Option<FSGroup>,
            read_only: bool,
            expected_group_id: u32,
            expected_permission: u32,
        }

        let tests = &[
            TestData {
                mount_path: "foo",
                fs_group: None,
                read_only: false,
                expected_group_id: 0,
                expected_permission: 0,
            },
            TestData {
                mount_path: "rw_mount",
                fs_group: Some(FSGroup {
                    group_id: 3000,
                    group_change_policy: FSGroupChangePolicy::Always.into(),
                    ..Default::default()
                }),
                read_only: false,
                expected_group_id: 3000,
                expected_permission: RW_MASK | EXEC_MASK | MODE_SETGID,
            },
            TestData {
                mount_path: "ro_mount",
                fs_group: Some(FSGroup {
                    group_id: 3000,
                    group_change_policy: FSGroupChangePolicy::OnRootMismatch.into(),
                    ..Default::default()
                }),
                read_only: true,
                expected_group_id: 3000,
                expected_permission: RO_MASK | EXEC_MASK | MODE_SETGID,
            },
        ];

        let tempdir = tempdir().expect("failed to create tmpdir");

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let mount_dir = tempdir.path().join(d.mount_path);
            fs::create_dir(&mount_dir)
                .unwrap_or_else(|_| panic!("{}: failed to create root directory", msg));

            let directory_mode = mount_dir.as_path().metadata().unwrap().permissions().mode();
            let mut storage_data = Storage::new();
            if d.read_only {
                storage_data.set_options(vec!["foo".to_string(), "ro".to_string()]);
            }
            if let Some(fs_group) = d.fs_group.clone() {
                storage_data.set_fs_group(fs_group);
            }
            storage_data.mount_point = mount_dir.clone().into_os_string().into_string().unwrap();

            let result = set_ownership(&logger, &storage_data);
            assert!(result.is_ok());

            assert_eq!(
                mount_dir.as_path().metadata().unwrap().gid(),
                d.expected_group_id
            );
            assert_eq!(
                mount_dir.as_path().metadata().unwrap().permissions().mode(),
                (directory_mode | d.expected_permission)
            );
        }
    }

    #[test]
    fn test_recursive_ownership_change() {
        skip_if_not_root!();

        const COUNT: usize = 5;

        #[derive(Debug)]
        struct TestData<'a> {
            // Directory where the recursive ownership change should be performed on
            path: &'a str,

            // User ID for ownership change
            uid: u32,

            // Group ID for ownership change
            gid: u32,

            // Set when the permission should be read-only
            read_only: bool,

            // The expected permission of all directories after ownership change
            expected_permission_directory: u32,

            // The expected permission of all files after ownership change
            expected_permission_file: u32,
        }

        let tests = &[
            TestData {
                path: "no_gid_change",
                uid: 0,
                gid: 0,
                read_only: false,
                expected_permission_directory: 0,
                expected_permission_file: 0,
            },
            TestData {
                path: "rw_gid_change",
                uid: 0,
                gid: 3000,
                read_only: false,
                expected_permission_directory: RW_MASK | EXEC_MASK | MODE_SETGID,
                expected_permission_file: RW_MASK,
            },
            TestData {
                path: "ro_gid_change",
                uid: 0,
                gid: 3000,
                read_only: true,
                expected_permission_directory: RO_MASK | EXEC_MASK | MODE_SETGID,
                expected_permission_file: RO_MASK,
            },
        ];

        let tempdir = tempdir().expect("failed to create tmpdir");

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let mount_dir = tempdir.path().join(d.path);
            fs::create_dir(&mount_dir)
                .unwrap_or_else(|_| panic!("{}: failed to create root directory", msg));

            let directory_mode = mount_dir.as_path().metadata().unwrap().permissions().mode();
            let mut file_mode: u32 = 0;

            // create testing directories and files
            for n in 1..COUNT {
                let nest_dir = mount_dir.join(format!("nested{n}"));
                fs::create_dir(&nest_dir)
                    .unwrap_or_else(|_| panic!("{}: failed to create nest directory", msg));

                for f in 1..COUNT {
                    let filename = nest_dir.join(format!("file{f}"));
                    File::create(&filename)
                        .unwrap_or_else(|_| panic!("{}: failed to create file", msg));
                    file_mode = filename.as_path().metadata().unwrap().permissions().mode();
                }
            }

            let uid = if d.uid > 0 {
                Some(Uid::from_raw(d.uid))
            } else {
                None
            };
            let gid = if d.gid > 0 {
                Some(Gid::from_raw(d.gid))
            } else {
                None
            };
            let result = recursive_ownership_change(&mount_dir, uid, gid, d.read_only);

            assert!(result.is_ok());

            assert_eq!(mount_dir.as_path().metadata().unwrap().gid(), d.gid);
            assert_eq!(
                mount_dir.as_path().metadata().unwrap().permissions().mode(),
                (directory_mode | d.expected_permission_directory)
            );

            for n in 1..COUNT {
                let nest_dir = mount_dir.join(format!("nested{n}"));
                for f in 1..COUNT {
                    let filename = nest_dir.join(format!("file{f}"));
                    let file = Path::new(&filename);

                    assert_eq!(file.metadata().unwrap().gid(), d.gid);
                    assert_eq!(
                        file.metadata().unwrap().permissions().mode(),
                        (file_mode | d.expected_permission_file)
                    );
                }

                let dir = Path::new(&nest_dir);
                assert_eq!(dir.metadata().unwrap().gid(), d.gid);
                assert_eq!(
                    dir.metadata().unwrap().permissions().mode(),
                    (directory_mode | d.expected_permission_directory)
                );
            }
        }
    }

    #[test]
    fn test_recursive_ownership_change_reports_operation() {
        let tempdir = tempdir().unwrap();
        let missing = tempdir.path().join("missing");

        let error = recursive_ownership_change(&missing, None, Some(Gid::from_raw(3000)), false)
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("change ownership during recursive fsGroup ownership")
        );
    }

    #[test]
    fn test_recursive_ownership_change_never_follows_symlinks() {
        let tempdir = tempdir().unwrap();
        let mount_dir = tempdir.path().join("volume");
        let inside = mount_dir.join("inside");
        let outside = tempdir.path().join("outside");
        fs::create_dir(&mount_dir).unwrap();
        fs::write(&inside, "inside").unwrap();
        fs::write(&outside, "outside").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();

        symlink(&outside, mount_dir.join("absolute-link")).unwrap();
        symlink("../outside", mount_dir.join("relative-link")).unwrap();
        symlink(".", mount_dir.join("ancestor-cycle")).unwrap();

        recursive_ownership_change(&mount_dir, None, Some(nix::unistd::getegid()), false).unwrap();

        assert_eq!(
            outside.metadata().unwrap().permissions().mode() & 0o777,
            0o600,
            "fsGroup traversal changed an out-of-volume symlink target"
        );
        assert_eq!(
            inside.metadata().unwrap().permissions().mode() & RW_MASK,
            RW_MASK,
            "fsGroup traversal did not update a regular in-volume file"
        );
    }

    #[test]
    fn test_recursive_ownership_change_rejects_symlinked_root() {
        let tempdir = tempdir().unwrap();
        let mount_dir = tempdir.path().join("volume");
        let mount_link = tempdir.path().join("volume-link");
        fs::create_dir(&mount_dir).unwrap();
        symlink(&mount_dir, &mount_link).unwrap();

        let error =
            recursive_ownership_change(&mount_link, None, Some(nix::unistd::getegid()), false)
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("resolve fsGroup mount path without symlinks"),
            "unexpected symlinked-root error: {:#}",
            error,
        );
    }

    #[test]
    fn test_recursive_ownership_change_rename_race_cannot_escape_root() {
        let tempdir = tempdir().unwrap();
        let mount_dir = tempdir.path().join("volume");
        let victim = mount_dir.join("victim");
        let parked = mount_dir.join("victim-parked");
        let outside = tempdir.path().join("outside");
        fs::create_dir(&mount_dir).unwrap();
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("inside"), "inside").unwrap();
        fs::write(&outside, "outside").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let racer_stop = stop.clone();
        let racer_victim = victim.clone();
        let racer_parked = parked.clone();
        let racer_outside = outside.clone();
        let racer = thread::spawn(move || {
            while !racer_stop.load(Ordering::Relaxed) {
                if fs::rename(&racer_victim, &racer_parked).is_ok() {
                    let _ = symlink(&racer_outside, &racer_victim);
                    thread::yield_now();
                    let _ = fs::remove_file(&racer_victim);
                    let _ = fs::rename(&racer_parked, &racer_victim);
                }
            }
        });

        for _ in 0..64 {
            // A concurrent rename may make the operation inconclusive. It may
            // never authorize the raced symlink target outside the root.
            let _ =
                recursive_ownership_change(&mount_dir, None, Some(nix::unistd::getegid()), false);
        }
        stop.store(true, Ordering::Relaxed);
        racer.join().unwrap();

        assert_eq!(
            outside.metadata().unwrap().permissions().mode() & 0o777,
            0o600,
            "rename race changed an out-of-volume sentinel"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cleanup_storage() {
        skip_if_not_root!();

        let logger = slog::Logger::root(slog::Discard, o!());

        let tmpdir = Builder::new().tempdir().unwrap();
        let tmpdir_path = tmpdir.path().to_str().unwrap();

        let srcdir = Builder::new()
            .prefix("src")
            .tempdir_in(tmpdir_path)
            .unwrap();
        let srcdir_path = srcdir.path().to_str().unwrap();
        let empty_file = Path::new(srcdir_path).join("emptyfile");
        fs::write(&empty_file, "test").unwrap();

        let destdir = Builder::new()
            .prefix("dest")
            .tempdir_in(tmpdir_path)
            .unwrap();
        let destdir_path = destdir.path().to_str().unwrap();

        let emptydir = Builder::new()
            .prefix("empty")
            .tempdir_in(tmpdir_path)
            .unwrap();

        let s = StorageDeviceGeneric::default();
        assert!(s.cleanup().is_ok());

        let s = StorageDeviceGeneric::new("".to_string());
        assert!(s.cleanup().is_ok());

        let invalid_dir = emptydir
            .path()
            .join("invalid")
            .to_str()
            .unwrap()
            .to_string();
        let s = StorageDeviceGeneric::new(invalid_dir);
        assert!(s.cleanup().is_ok());

        assert!(bind_mount(srcdir_path, destdir_path, &logger).is_ok());

        let s = StorageDeviceGeneric::new(destdir_path.to_string());
        assert!(s.cleanup().is_ok());

        // fail to remove non-empty directory
        let s = StorageDeviceGeneric::new(srcdir_path.to_string());
        s.cleanup().unwrap_err();

        // remove a directory without umount
        fs::remove_file(&empty_file).unwrap();
        s.cleanup().unwrap();
    }

    fn bind_mount(src: &str, dst: &str, logger: &Logger) -> Result<(), Error> {
        let src_path = Path::new(src);
        let dst_path = Path::new(dst);

        baremount(src_path, dst_path, "bind", MsFlags::MS_BIND, "", logger)
    }
}
