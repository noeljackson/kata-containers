// Copyright (c) 2023 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use kata_sys_util::mount::{get_mount_path, get_mount_type};
use kata_types::mount::{record_direct_volume_sandbox_id, DirectVolumeMountInfo};
use nix::sys::{stat, stat::SFlag};
use oci_spec::runtime as oci;
use tokio::sync::RwLock;

use crate::volume::{
    direct_volumes::{
        get_direct_volume_path, rawblock_volume, spdk_volume, vfio_volume, volume_mount_info,
        KATA_DIRECT_VOLUME_TYPE, KATA_SPDK_VOLUME_TYPE, KATA_SPOOL_VOLUME_TYPE,
        KATA_VFIO_VOLUME_TYPE,
    },
    utils::KATA_MOUNT_BIND_TYPE,
    Volume,
};

enum DirectVolumeType {
    RawBlock,
    Spdk,
    Vfio,
}

pub(crate) struct HandledDirectVolume {
    pub(crate) volume: Arc<dyn Volume>,
    pub(crate) confidential_binding: Option<ConfidentialDirectVolumeBinding>,
}

/// One confidential direct volume can be mounted at several destinations in a
/// container. The first mount owns the single agent Storage request; later
/// mounts reuse its guest path without attaching or activating the device
/// again.
pub(crate) struct ConfidentialDirectVolumeBinding {
    mount_info: DirectVolumeMountInfo,
    host_source: PathBuf,
    mount_type: String,
    mount_options: Option<Vec<String>>,
    read_only: bool,
    guest_mount: oci::Mount,
    destinations: HashSet<PathBuf>,
}

impl ConfidentialDirectVolumeBinding {
    fn new(
        m: &oci::Mount,
        mount_info: &DirectVolumeMountInfo,
        read_only: bool,
        volume: &dyn Volume,
    ) -> Result<Self> {
        let host_source = m
            .source()
            .clone()
            .context("confidential direct volume mount source is missing")?;
        let mounts = volume
            .get_volume_mount()
            .context("get confidential direct volume mount")?;
        ensure!(
            mounts.len() == 1,
            "confidential direct volume must produce exactly one initial mount"
        );
        let storages = volume
            .get_storage()
            .context("get confidential direct volume storage")?;
        ensure!(
            storages.len() == 1 && storages[0].confidential_storage.is_some(),
            "confidential direct volume must produce exactly one typed Storage request"
        );

        let guest_mount = mounts
            .into_iter()
            .next()
            .context("confidential direct volume initial mount is missing")?;

        Ok(Self {
            mount_info: mount_info.clone(),
            host_source,
            mount_type: get_mount_type(m),
            mount_options: m.options().clone(),
            read_only,
            guest_mount,
            destinations: HashSet::from([m.destination().clone()]),
        })
    }

    pub(crate) fn reuse(
        &mut self,
        m: &oci::Mount,
        mount_info: &DirectVolumeMountInfo,
        read_only: bool,
    ) -> Result<Arc<dyn Volume>> {
        ensure!(
            mount_info == &self.mount_info,
            "confidential direct volume aliases must preserve typed mount metadata"
        );
        ensure!(
            m.source().as_ref() == Some(&self.host_source),
            "confidential direct volume aliases must preserve the host source"
        );
        ensure!(
            get_mount_type(m) == self.mount_type,
            "confidential direct volume aliases must preserve the mount type"
        );
        ensure!(
            m.options() == &self.mount_options,
            "confidential direct volume aliases must preserve mount options"
        );
        ensure!(
            read_only == self.read_only,
            "confidential direct volume aliases must preserve access intent"
        );
        ensure!(
            self.destinations.insert(m.destination().clone()),
            "confidential direct volume contains a duplicate destination"
        );

        let mut mount = self.guest_mount.clone();
        mount.set_destination(m.destination().clone());
        Ok(Arc::new(ConfidentialDirectVolumeAlias { mount }))
    }
}

struct ConfidentialDirectVolumeAlias {
    mount: oci::Mount,
}

#[async_trait]
impl Volume for ConfidentialDirectVolumeAlias {
    fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
        Ok(vec![self.mount.clone()])
    }

    fn get_storage(&self) -> Result<Vec<agent::Storage>> {
        Ok(Vec::new())
    }

    fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        Ok(())
    }
}

fn to_volume_type(volume_type: &str) -> DirectVolumeType {
    match volume_type {
        KATA_SPDK_VOLUME_TYPE | KATA_SPOOL_VOLUME_TYPE => DirectVolumeType::Spdk,
        KATA_VFIO_VOLUME_TYPE => DirectVolumeType::Vfio,
        _ => DirectVolumeType::RawBlock,
    }
}

pub(crate) async fn handle_direct_volume(
    d: &RwLock<DeviceManager>,
    m: &oci::Mount,
    volume_path: &str,
    mount_info: &DirectVolumeMountInfo,
    read_only: bool,
    sid: &str,
) -> Result<HandledDirectVolume> {
    let confidential = mount_info.validated_confidential_storage()?.is_some();
    let direct_volume: Arc<dyn Volume> = match to_volume_type(mount_info.volume_type.as_str()) {
        DirectVolumeType::RawBlock => Arc::new(
            rawblock_volume::RawblockVolume::new(d, m, mount_info, read_only, sid)
                .await
                .with_context(|| format!("new sid {:?} rawblock volume {:?}", &sid, m))?,
        ),
        DirectVolumeType::Spdk => Arc::new(
            spdk_volume::SPDKVolume::new(d, m, mount_info, read_only, sid)
                .await
                .with_context(|| format!("create spdk volume {m:?}"))?,
        ),
        DirectVolumeType::Vfio => Arc::new(
            vfio_volume::VfioVolume::new(d, m, mount_info, read_only, sid)
                .await
                .with_context(|| format!("new vfio volume {m:?}"))?,
        ),
    };

    record_direct_volume_sandbox_id(volume_path, sid)
        .context("record direct-volume runtime-rs sandbox mapping")?;

    let confidential_binding = confidential
        .then(|| {
            ConfidentialDirectVolumeBinding::new(m, mount_info, read_only, direct_volume.as_ref())
        })
        .transpose()?;

    Ok(HandledDirectVolume {
        volume: direct_volume,
        confidential_binding,
    })
}

pub(crate) fn direct_volume_mount_info(m: &oci::Mount) -> Result<(String, DirectVolumeMountInfo)> {
    let volume_path = get_mount_path(m.source());
    let mount_info = volume_mount_info(&volume_path)?;

    Ok((volume_path, mount_info))
}

pub(crate) fn is_direct_volume(m: &oci::Mount) -> Result<bool> {
    let mnt_type = get_mount_type(m);
    let mount_type = mnt_type.as_str();

    // Filter the non-bind volume and non-direct-vol volume
    let vol_types = [
        KATA_MOUNT_BIND_TYPE,
        KATA_DIRECT_VOLUME_TYPE,
        KATA_VFIO_VOLUME_TYPE,
        KATA_SPDK_VOLUME_TYPE,
        KATA_SPOOL_VOLUME_TYPE,
    ];
    if !vol_types.contains(&mount_type) {
        return Ok(false);
    }

    match get_direct_volume_path(get_mount_path(m.source()).as_str()) {
        Ok(directvol_path) => {
            let fstat = stat::stat(directvol_path.as_str())
                .context(format!("stat mount source {directvol_path} failed."))?;
            Ok(SFlag::from_bits_truncate(fstat.st_mode) == SFlag::S_IFDIR)
        }
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVolume {
        mount: oci::Mount,
        storage: agent::Storage,
    }

    #[async_trait]
    impl Volume for TestVolume {
        fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
            Ok(vec![self.mount.clone()])
        }

        fn get_storage(&self) -> Result<Vec<agent::Storage>> {
            Ok(vec![self.storage.clone()])
        }

        fn get_device_id(&self) -> Result<Option<String>> {
            Ok(Some("test-device".to_string()))
        }

        async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
            Ok(())
        }
    }

    fn host_mount(destination: &str) -> oci::Mount {
        let mut mount = oci::Mount::default();
        mount.set_source(Some(PathBuf::from("/run/kata/direct-volumes/workspace")));
        mount.set_destination(PathBuf::from(destination));
        mount.set_typ(Some("bind".to_string()));
        mount.set_options(Some(vec![
            "rbind".to_string(),
            "rprivate".to_string(),
            "rw".to_string(),
        ]));
        mount
    }

    fn test_volume() -> TestVolume {
        let mut mount = host_mount("/home/codewire");
        mount.set_source(Some(PathBuf::from(
            "/run/kata-containers/shared/containers/passthrough/confidential-test",
        )));
        TestVolume {
            mount,
            storage: agent::Storage {
                confidential_storage: Some(agent::ConfidentialStorage {
                    manifest_uri: "kbs:///tenant/storage-manifests/workspace-v1".to_string(),
                    requested_access: agent::ConfidentialStorageAccess::ReadWrite,
                }),
                ..Default::default()
            },
        }
    }

    fn test_mount_info() -> DirectVolumeMountInfo {
        DirectVolumeMountInfo {
            volume_type: KATA_DIRECT_VOLUME_TYPE.to_string(),
            device: "/dev/longhorn/workspace".to_string(),
            fs_type: kata_types::mount::KATA_CONFIDENTIAL_STORAGE_FS_TYPE.to_string(),
            confidential_storage: Some(kata_types::mount::ConfidentialStorage {
                manifest_uri: "kbs:///tenant/storage-manifests/workspace-v1".to_string(),
                requested_access: kata_types::mount::ConfidentialStorageAccess::ReadWrite,
            }),
            ..Default::default()
        }
    }

    fn binding() -> ConfidentialDirectVolumeBinding {
        ConfidentialDirectVolumeBinding::new(
            &host_mount("/home/codewire"),
            &test_mount_info(),
            false,
            &test_volume(),
        )
        .unwrap()
    }

    #[test]
    fn additional_destination_reuses_guest_mount_without_another_storage() {
        let mut binding = binding();
        let alias = binding
            .reuse(&host_mount("/workspace"), &test_mount_info(), false)
            .unwrap();

        assert!(alias.get_storage().unwrap().is_empty());
        assert_eq!(alias.get_device_id().unwrap(), None);
        let mounts = alias.get_volume_mount().unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].destination(), &PathBuf::from("/workspace"));
        assert_eq!(
            mounts[0].source().as_ref(),
            Some(&PathBuf::from(
                "/run/kata-containers/shared/containers/passthrough/confidential-test"
            ))
        );
    }

    #[test]
    fn additional_destination_contract_changes_fail_closed() {
        let mut changed_source = host_mount("/workspace");
        changed_source.set_source(Some(PathBuf::from("/run/kata/direct-volumes/other")));
        assert!(binding()
            .reuse(&changed_source, &test_mount_info(), false)
            .is_err());

        let mut changed_options = host_mount("/workspace");
        changed_options.set_options(Some(vec!["rbind".to_string(), "ro".to_string()]));
        assert!(binding()
            .reuse(&changed_options, &test_mount_info(), true)
            .is_err());

        assert!(binding()
            .reuse(&host_mount("/workspace"), &test_mount_info(), true)
            .is_err());
        assert!(binding()
            .reuse(&host_mount("/home/codewire"), &test_mount_info(), false,)
            .is_err());

        let mut changed_metadata = test_mount_info();
        changed_metadata
            .metadata
            .insert("fsGroup".to_string(), "0".to_string());
        assert!(binding()
            .reuse(&host_mount("/workspace"), &changed_metadata, false)
            .is_err());
    }

    #[test]
    fn binding_requires_one_typed_storage() {
        let mut untyped = test_volume();
        untyped.storage.confidential_storage = None;
        assert!(ConfidentialDirectVolumeBinding::new(
            &host_mount("/home/codewire"),
            &test_mount_info(),
            false,
            &untyped,
        )
        .is_err());
    }
}
