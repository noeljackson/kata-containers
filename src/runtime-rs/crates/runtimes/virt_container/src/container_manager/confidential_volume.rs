// Copyright (c) 2026 Codewire, Inc.
//
// SPDX-License-Identifier: Apache-2.0

//! Convert opted-in Kubernetes raw block devices into typed guest-confidential storage.

use std::path::{Path, PathBuf};

use agent::types::{
    ConfidentialStorage, ConfidentialStorageAccess, FSGroup, FSGroupChangePolicy, Storage,
};
use anyhow::{anyhow, Context, Result};
use kata_types::annotations::KATA_ANNO_CONFIDENTIAL_VOLUME;
use kata_types::confidential_volume::{
    confidential_storage_mount_name, parse_confidential_volume_declarations,
    ConfidentialFSGroupChangePolicy, KATA_CONFIDENTIAL_STORAGE_FS_TYPE,
    KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT,
};
use kata_types::config::hypervisor::SharedFsInfo;
use kata_types::device::{DRIVER_BLK_PCI_TYPE, DRIVER_SCSI_TYPE};
use kata_types::k8s;
use oci_spec::runtime as oci;
use resource::cdi_devices::ContainerDevice;

const CONFIDENTIAL_MAPPER_PREFIX: &str = "/dev/mapper/coco-pv-";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsumedDeviceIdentity {
    id: String,
    field_type: String,
    vm_path: String,
    container_path: String,
    options: Vec<String>,
}

impl From<&agent::types::Device> for ConsumedDeviceIdentity {
    fn from(device: &agent::types::Device) -> Self {
        Self {
            id: device.id.clone(),
            field_type: device.field_type.clone(),
            vm_path: device.vm_path.clone(),
            container_path: device.container_path.clone(),
            options: device.options.clone(),
        }
    }
}

impl ConsumedDeviceIdentity {
    fn matches(&self, device: &agent::types::Device) -> bool {
        self == &Self::from(device)
    }

    fn same_source(&self, device: &agent::types::Device) -> bool {
        (self.field_type == device.field_type && self.id == device.id)
            || (!self.vm_path.is_empty() && self.vm_path == device.vm_path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsumedOciBlockIdentity {
    path: PathBuf,
    major: i64,
    minor: i64,
}

impl ConsumedOciBlockIdentity {
    fn matches(&self, device: &oci::LinuxDevice) -> bool {
        device.typ() == oci::LinuxDeviceType::B
            && device.path() == &self.path
            && device.major() == self.major
            && device.minor() == self.minor
    }

    fn same_device(&self, device: &oci::LinuxDevice) -> bool {
        device.typ() == oci::LinuxDeviceType::B
            && device.major() == self.major
            && device.minor() == self.minor
    }
}

/// Container-local result of consuming confidential raw block devices.
#[derive(Debug, Default)]
pub(super) struct ConfidentialVolumePlan {
    pub(super) storages: Vec<Storage>,
    pub(super) mounts: Vec<oci::Mount>,
    consumed_devices: Vec<ConsumedDeviceIdentity>,
    consumed_oci_devices: Vec<ConsumedOciBlockIdentity>,
}

impl ConfidentialVolumePlan {
    /// Remove consumed block devices from the Agent device list and OCI Linux devices.
    pub(super) fn consume_devices(
        &self,
        spec: &mut oci::Spec,
        devices: Vec<ContainerDevice>,
    ) -> Result<Vec<ContainerDevice>> {
        if self.consumed_devices.is_empty() {
            return Ok(devices);
        }

        for consumed in &self.consumed_devices {
            let matches = devices
                .iter()
                .filter(|device| consumed.matches(&device.device))
                .count();
            if matches != 1 {
                return Err(anyhow!(
                    "confidential device identity must be consumed exactly once"
                ));
            }
        }
        let remaining = devices
            .into_iter()
            .filter(|device| {
                !self
                    .consumed_devices
                    .iter()
                    .any(|consumed| consumed.matches(&device.device))
            })
            .collect();

        let linux = spec
            .linux_mut()
            .as_mut()
            .context("OCI spec missing linux field")?;
        let mut linux_devices = linux.devices().clone().unwrap_or_default();
        for consumed in &self.consumed_oci_devices {
            let matches = linux_devices
                .iter()
                .filter(|device| consumed.matches(device))
                .count();
            if matches != 1 {
                return Err(anyhow!(
                    "confidential OCI block identity must be consumed exactly once"
                ));
            }
        }
        linux_devices.retain(|device| {
            !self
                .consumed_oci_devices
                .iter()
                .any(|consumed| consumed.matches(device))
        });
        linux.set_devices((!linux_devices.is_empty()).then_some(linux_devices));

        Ok(remaining)
    }
}

/// Build the typed storage and filesystem mounts for the current Kubernetes container.
pub(super) fn build_confidential_volume_plan(
    spec: &mut oci::Spec,
    devices: &[ContainerDevice],
    selected_shared_fs: Option<&SharedFsInfo>,
) -> Result<ConfidentialVolumePlan> {
    let annotations = spec.annotations().as_ref();
    let Some(raw) = annotations
        .and_then(|values| values.get(KATA_ANNO_CONFIDENTIAL_VOLUME))
        .cloned()
    else {
        return Ok(ConfidentialVolumePlan::default());
    };
    match selected_shared_fs {
        Some(shared_fs) if shared_fs.shared_fs.is_none() => {}
        Some(shared_fs) => {
            return Err(anyhow!(
                "confidential storage requires shared_fs=none; selected hypervisor uses {:?}",
                shared_fs.shared_fs
            ));
        }
        None => {
            return Err(anyhow!(
                "confidential storage requires an unambiguous selected hypervisor with shared_fs=none"
            ));
        }
    }
    let declarations = parse_confidential_volume_declarations(&raw)
        .context("parse confidential volume annotation")?;
    spec.annotations_mut()
        .as_mut()
        .expect("the confidential annotation came from this map")
        .remove(KATA_ANNO_CONFIDENTIAL_VOLUME);
    let container_name = k8s::container_name(spec);
    let existing_mounts = spec.mounts().as_ref().map(Vec::as_slice).unwrap_or(&[]);
    let mut plan = ConfidentialVolumePlan::default();

    for (volume_name, declaration) in declarations {
        let matching_devices = devices
            .iter()
            .filter(|device| device.device.container_path == declaration.device_path)
            .collect::<Vec<_>>();
        let Some(destinations) = declaration.mounts.0.get(&container_name) else {
            if !matching_devices.is_empty() {
                return Err(anyhow!(
                    "confidential volume {volume_name:?} exposes its raw device to undeclared container {container_name:?}"
                ));
            }
            continue;
        };
        if matching_devices.len() != 1 {
            return Err(anyhow!(
                "confidential volume {volume_name:?} must resolve exactly one raw block device at {:?}",
                declaration.device_path
            ));
        }
        let device = &matching_devices[0].device;
        if device.id.is_empty()
            || !matches!(
                device.field_type.as_str(),
                DRIVER_BLK_PCI_TYPE | DRIVER_SCSI_TYPE
            )
            || device.vm_path.starts_with(CONFIDENTIAL_MAPPER_PREFIX)
            || !device.options.is_empty()
        {
            return Err(anyhow!(
                "confidential volume {volume_name:?} resolved an invalid guest block device identity"
            ));
        }
        let consumed_device = ConsumedDeviceIdentity::from(device);
        if devices.iter().any(|candidate| {
            candidate.device.container_path != device.container_path
                && consumed_device.same_source(&candidate.device)
        }) {
            return Err(anyhow!(
                "confidential volume {volume_name:?} block identity is aliased by another device request"
            ));
        }

        let consumed_oci_device = {
            let linux = spec
                .linux()
                .as_ref()
                .context("OCI spec missing linux field")?;
            let linux_devices = linux.devices().as_deref().unwrap_or(&[]);
            let matching_oci_devices = linux_devices
                .iter()
                .filter(|candidate| {
                    candidate.path().as_path() == Path::new(&declaration.device_path)
                })
                .collect::<Vec<_>>();
            if matching_oci_devices.len() != 1
                || matching_oci_devices[0].typ() != oci::LinuxDeviceType::B
            {
                return Err(anyhow!(
                    "confidential volume {volume_name:?} must identify exactly one OCI block device"
                ));
            }
            let identity = ConsumedOciBlockIdentity {
                path: matching_oci_devices[0].path().clone(),
                major: matching_oci_devices[0].major(),
                minor: matching_oci_devices[0].minor(),
            };
            if linux_devices.iter().any(|candidate| {
                candidate.path() != &identity.path && identity.same_device(candidate)
            }) {
                return Err(anyhow!(
                    "confidential volume {volume_name:?} block identity is aliased by another OCI device"
                ));
            }
            identity
        };
        for destination in destinations {
            if existing_mounts
                .iter()
                .any(|mount| mount.destination().as_path() == Path::new(destination))
                || plan
                    .mounts
                    .iter()
                    .any(|mount| mount.destination().as_path() == Path::new(destination))
            {
                return Err(anyhow!(
                    "confidential volume {volume_name:?} collides with existing mount destination {destination:?}"
                ));
            }
        }

        let mount_name = confidential_storage_mount_name(&declaration.manifest_uri)?;
        let mount_point = format!("{KATA_CONFIDENTIAL_STORAGE_MOUNT_ROOT}/{mount_name}");
        let fs_group = declaration.fs_group.map(|group_id| FSGroup {
            group_id,
            group_change_policy: match declaration.fs_group_change_policy {
                Some(ConfidentialFSGroupChangePolicy::OnRootMismatch) => {
                    FSGroupChangePolicy::OnRootMismatch
                }
                None | Some(ConfidentialFSGroupChangePolicy::Always) => FSGroupChangePolicy::Always,
            },
        });
        plan.storages.push(Storage {
            driver: device.field_type.clone(),
            source: device.id.clone(),
            fs_type: KATA_CONFIDENTIAL_STORAGE_FS_TYPE.to_string(),
            fs_group,
            mount_point: mount_point.clone(),
            confidential_storage: Some(ConfidentialStorage {
                manifest_uri: declaration.manifest_uri,
                requested_access: ConfidentialStorageAccess::ReadWrite,
            }),
            ..Default::default()
        });
        for destination in destinations {
            let mut mount = oci::Mount::default();
            mount.set_destination(PathBuf::from(destination));
            mount.set_typ(Some("bind".to_string()));
            mount.set_source(Some(PathBuf::from(&mount_point)));
            mount.set_options(Some(vec![
                "rbind".to_string(),
                "rprivate".to_string(),
                "rw".to_string(),
            ]));
            plan.mounts.push(mount);
        }
        plan.consumed_devices.push(consumed_device);
        plan.consumed_oci_devices.push(consumed_oci_device);
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use agent::types::Device;
    use oci_spec::runtime::{LinuxBuilder, LinuxDeviceBuilder, LinuxDeviceType, SpecBuilder};

    use super::*;

    const DECLARATION: &str = r#"{
        "workspace": {
            "devicePath": "/dev/confidential-workspace",
            "manifestUri": "kbs:///tenant/storage-manifests/workspace-v1",
            "access": "readWrite",
            "fsGroup": 1000,
            "fsGroupChangePolicy": "OnRootMismatch",
            "mounts": {"workspace": ["/home/workspace", "/workspace"]}
        }
    }"#;

    const SHARED_DECLARATION: &str = r#"{
        "workspace": {
            "devicePath": "/dev/confidential-workspace",
            "manifestUri": "kbs:///tenant/storage-manifests/workspace-v1",
            "access": "readWrite",
            "fsGroup": 1000,
            "fsGroupChangePolicy": "OnRootMismatch",
            "mounts": {
                "workspace": ["/home/workspace", "/workspace"],
                "dind": ["/workspace"]
            }
        }
    }"#;

    fn spec(container_name: &str, declaration: Option<&str>) -> oci::Spec {
        let mut annotations = HashMap::from([(
            "io.kubernetes.cri.container-name".to_string(),
            container_name.to_string(),
        )]);
        if let Some(declaration) = declaration {
            annotations.insert(
                KATA_ANNO_CONFIDENTIAL_VOLUME.to_string(),
                declaration.to_string(),
            );
        }
        let linux_device = LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/confidential-workspace"))
            .typ(LinuxDeviceType::B)
            .major(8_i64)
            .minor(1_i64)
            .build()
            .unwrap();
        SpecBuilder::default()
            .annotations(annotations)
            .linux(
                LinuxBuilder::default()
                    .devices(vec![linux_device])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn raw_device() -> ContainerDevice {
        ContainerDevice {
            device_info: None,
            device: Device {
                id: "00/00".to_string(),
                field_type: "blk".to_string(),
                vm_path: "/dev/vda".to_string(),
                container_path: "/dev/confidential-workspace".to_string(),
                options: Vec::new(),
            },
        }
    }

    fn ordinary_device() -> ContainerDevice {
        ContainerDevice {
            device_info: None,
            device: Device {
                id: "01/00".to_string(),
                field_type: "blk".to_string(),
                vm_path: "/dev/vdb".to_string(),
                container_path: "/dev/ordinary".to_string(),
                options: Vec::new(),
            },
        }
    }

    fn disabled_shared_fs() -> SharedFsInfo {
        SharedFsInfo::default()
    }

    #[test]
    fn translates_and_consumes_raw_device() {
        let mut spec = spec("workspace", Some(DECLARATION));
        let plan =
            build_confidential_volume_plan(&mut spec, &[raw_device()], Some(&disabled_shared_fs()))
                .unwrap();

        assert_eq!(plan.storages.len(), 1);
        assert_eq!(plan.mounts.len(), 2);
        assert_eq!(plan.storages[0].driver, "blk");
        assert_eq!(plan.storages[0].source, "00/00");
        assert_eq!(
            plan.storages[0]
                .confidential_storage
                .as_ref()
                .unwrap()
                .manifest_uri,
            "kbs:///tenant/storage-manifests/workspace-v1"
        );
        assert_eq!(
            plan.storages[0].fs_group,
            Some(FSGroup {
                group_id: 1000,
                group_change_policy: FSGroupChangePolicy::OnRootMismatch,
            })
        );
        let remaining = plan.consume_devices(&mut spec, vec![raw_device()]).unwrap();
        assert!(remaining.is_empty());
        assert!(spec.linux().as_ref().unwrap().devices().is_none());
        assert!(!spec
            .annotations()
            .as_ref()
            .unwrap()
            .contains_key(KATA_ANNO_CONFIDENTIAL_VOLUME));
    }

    #[test]
    fn ordinary_devices_are_unchanged_without_opt_in() {
        let mut spec = spec("workspace", None);
        let plan = build_confidential_volume_plan(&mut spec, &[raw_device()], None).unwrap();
        let remaining = plan.consume_devices(&mut spec, vec![raw_device()]).unwrap();
        assert!(plan.storages.is_empty());
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            spec.linux()
                .as_ref()
                .unwrap()
                .devices()
                .as_ref()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_missing_or_enabled_shared_fs_before_building_storage() {
        for shared_fs_name in ["virtio-fs", "inline-virtio-fs", "virtio-fs-nydus", "9p"] {
            let mut spec = spec("workspace", Some(DECLARATION));
            let shared_fs = SharedFsInfo {
                shared_fs: Some(shared_fs_name.to_string()),
                ..Default::default()
            };
            let error =
                build_confidential_volume_plan(&mut spec, &[raw_device()], Some(&shared_fs))
                    .unwrap_err();
            assert!(error.to_string().contains("requires shared_fs=none"));
            assert!(spec
                .annotations()
                .as_ref()
                .unwrap()
                .contains_key(KATA_ANNO_CONFIDENTIAL_VOLUME));
        }

        let mut spec = spec("workspace", Some(DECLARATION));
        let error = build_confidential_volume_plan(&mut spec, &[raw_device()], None).unwrap_err();
        assert!(error
            .to_string()
            .contains("unambiguous selected hypervisor"));
        assert!(spec
            .annotations()
            .as_ref()
            .unwrap()
            .contains_key(KATA_ANNO_CONFIDENTIAL_VOLUME));
    }

    #[test]
    fn consumes_only_the_declared_device_from_mixed_input() {
        let mut spec = spec("workspace", Some(DECLARATION));
        let plan = build_confidential_volume_plan(
            &mut spec,
            &[raw_device(), ordinary_device()],
            Some(&disabled_shared_fs()),
        )
        .unwrap();
        let remaining = plan
            .consume_devices(&mut spec, vec![raw_device(), ordinary_device()])
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].device.container_path, "/dev/ordinary");
    }

    #[test]
    fn shares_one_stable_guest_activation_across_declared_containers() {
        let mut workspace = spec("workspace", Some(SHARED_DECLARATION));
        let mut dind = spec("dind", Some(SHARED_DECLARATION));
        let workspace_plan = build_confidential_volume_plan(
            &mut workspace,
            &[raw_device()],
            Some(&disabled_shared_fs()),
        )
        .unwrap();
        let dind_plan =
            build_confidential_volume_plan(&mut dind, &[raw_device()], Some(&disabled_shared_fs()))
                .unwrap();

        assert_eq!(workspace_plan.storages.len(), 1);
        assert_eq!(dind_plan.storages.len(), 1);
        assert_eq!(
            workspace_plan.storages[0].mount_point, dind_plan.storages[0].mount_point,
            "the Agent can reference-count one sandbox-scoped activation"
        );
        assert_eq!(workspace_plan.mounts.len(), 2);
        assert_eq!(dind_plan.mounts.len(), 1);
    }

    #[test]
    fn rejects_missing_duplicate_or_undeclared_device_use() {
        let mut workspace_spec = spec("workspace", Some(DECLARATION));
        assert!(build_confidential_volume_plan(
            &mut workspace_spec,
            &[],
            Some(&disabled_shared_fs())
        )
        .is_err());
        let mut workspace_spec = spec("workspace", Some(DECLARATION));
        assert!(build_confidential_volume_plan(
            &mut workspace_spec,
            &[raw_device(), raw_device()],
            Some(&disabled_shared_fs())
        )
        .is_err());

        let mut spec = spec("other", Some(DECLARATION));
        assert!(build_confidential_volume_plan(
            &mut spec,
            &[raw_device()],
            Some(&disabled_shared_fs())
        )
        .is_err());
    }

    #[test]
    fn rejects_existing_mount_collision() {
        let mut spec = spec("workspace", Some(DECLARATION));
        let mut mount = oci::Mount::default();
        mount.set_destination(PathBuf::from("/workspace"));
        spec.set_mounts(Some(vec![mount]));
        assert!(build_confidential_volume_plan(
            &mut spec,
            &[raw_device()],
            Some(&disabled_shared_fs())
        )
        .is_err());
    }

    #[test]
    fn rejects_agent_source_identity_aliases() {
        let mut spec = spec("workspace", Some(DECLARATION));
        let confidential = raw_device();
        let mut alias = ordinary_device();
        alias.device.id.clone_from(&confidential.device.id);

        let error = build_confidential_volume_plan(
            &mut spec,
            &[confidential, alias],
            Some(&disabled_shared_fs()),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("aliased by another device request"));
    }

    #[test]
    fn rejects_oci_major_minor_aliases() {
        let mut spec = spec("workspace", Some(DECLARATION));
        spec.linux_mut()
            .as_mut()
            .unwrap()
            .devices_mut()
            .as_mut()
            .unwrap()
            .push(
                LinuxDeviceBuilder::default()
                    .path(PathBuf::from("/dev/ordinary"))
                    .typ(LinuxDeviceType::B)
                    .major(8_i64)
                    .minor(1_i64)
                    .build()
                    .unwrap(),
            );

        let error =
            build_confidential_volume_plan(&mut spec, &[raw_device()], Some(&disabled_shared_fs()))
                .unwrap_err();
        assert!(error.to_string().contains("aliased by another OCI device"));
    }

    #[test]
    fn consumes_only_the_bound_device_identities() {
        let mut spec = spec("workspace", Some(DECLARATION));
        let plan =
            build_confidential_volume_plan(&mut spec, &[raw_device()], Some(&disabled_shared_fs()))
                .unwrap();
        let mut substituted = raw_device();
        substituted.device.id = "01/00".to_string();

        let error = plan
            .consume_devices(&mut spec, vec![substituted])
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("device identity must be consumed exactly once"));
    }

    #[test]
    fn rejects_confidential_mapper_paths_and_non_block_oci_types() {
        let mut mapper = raw_device();
        mapper.device.vm_path = "/dev/mapper/coco-pv-existing".to_string();
        let mut mapper_spec = spec("workspace", Some(DECLARATION));
        assert!(build_confidential_volume_plan(
            &mut mapper_spec,
            &[mapper],
            Some(&disabled_shared_fs())
        )
        .is_err());

        let mut char_spec = spec("workspace", Some(DECLARATION));
        char_spec
            .linux_mut()
            .as_mut()
            .unwrap()
            .devices_mut()
            .as_mut()
            .unwrap()[0]
            .set_typ(LinuxDeviceType::C);
        assert!(build_confidential_volume_plan(
            &mut char_spec,
            &[raw_device()],
            Some(&disabled_shared_fs())
        )
        .is_err());
    }
}
