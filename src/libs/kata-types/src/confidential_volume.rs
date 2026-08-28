// SPDX-License-Identifier: Apache-2.0

//! Strict declarations for turning a Kubernetes raw block device into guest-confidential
//! storage.
//!
//! CSI remains responsible only for provisioning and publishing the raw device. The runtime
//! consumes this measured declaration and converts the matching device into a typed Agent
//! storage request instead of exposing the raw device to the workload.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{anyhow, Result};
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::mount::{validate_confidential_manifest_uri, ConfidentialStorageAccess};

const MAX_DECLARATION_BYTES: usize = 64 * 1024;
const MAX_VOLUMES: usize = 32;
const MAX_MOUNTS_PER_CONTAINER: usize = 32;

/// The fsGroup ownership behavior requested for a confidential filesystem.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ConfidentialFSGroupChangePolicy {
    /// Always apply the requested group ownership.
    Always,
    /// Apply group ownership only when the root directory does not already match.
    OnRootMismatch,
}

/// A single measured confidential-volume declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfidentialVolumeDeclaration {
    /// Container-visible raw-device path supplied through Kubernetes `volumeDevices`.
    pub device_path: String,
    /// Immutable Trustee/KBS storage-manifest resource.
    pub manifest_uri: String,
    /// Requested storage access. Only read-write is currently supported.
    pub access: ConfidentialStorageAccess,
    /// Optional filesystem group to apply inside the guest.
    #[serde(default)]
    pub fs_group: Option<u32>,
    /// Optional filesystem group ownership behavior.
    #[serde(default)]
    pub fs_group_change_policy: Option<ConfidentialFSGroupChangePolicy>,
    /// Container names and their guest filesystem destinations.
    pub mounts: ConfidentialVolumeMounts,
}

/// Unique container-to-destination mappings for one confidential volume.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfidentialVolumeMounts(pub BTreeMap<String, Vec<String>>);

impl<'de> Deserialize<'de> for ConfidentialVolumeMounts {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MountsVisitor;

        impl<'de> Visitor<'de> for MountsVisitor {
            type Value = ConfidentialVolumeMounts;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a map of unique container mount declarations")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut mounts = BTreeMap::new();
                while let Some((name, destinations)) = map.next_entry()? {
                    if mounts.insert(name, destinations).is_some() {
                        return Err(A::Error::custom(
                            "duplicate confidential volume container declaration",
                        ));
                    }
                }
                Ok(ConfidentialVolumeMounts(mounts))
            }
        }

        deserializer.deserialize_map(MountsVisitor)
    }
}

struct ConfidentialVolumeDeclarations(BTreeMap<String, ConfidentialVolumeDeclaration>);

impl<'de> Deserialize<'de> for ConfidentialVolumeDeclarations {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeclarationsVisitor;

        impl<'de> Visitor<'de> for DeclarationsVisitor {
            type Value = ConfidentialVolumeDeclarations;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a map of unique confidential volume declarations")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut declarations = BTreeMap::new();
                while let Some((name, declaration)) = map.next_entry()? {
                    if declarations.insert(name, declaration).is_some() {
                        return Err(A::Error::custom(
                            "duplicate confidential volume declaration",
                        ));
                    }
                }
                Ok(ConfidentialVolumeDeclarations(declarations))
            }
        }

        deserializer.deserialize_map(DeclarationsVisitor)
    }
}

/// Parse and validate a complete confidential raw-block declaration annotation.
pub fn parse_confidential_volume_declarations(
    raw: &str,
) -> Result<BTreeMap<String, ConfidentialVolumeDeclaration>> {
    if raw.is_empty() || raw.len() > MAX_DECLARATION_BYTES {
        return Err(anyhow!(
            "confidential volume declaration must be between 1 and {MAX_DECLARATION_BYTES} bytes"
        ));
    }

    let ConfidentialVolumeDeclarations(declarations) = serde_json::from_str(raw)
        .map_err(|error| anyhow!("invalid confidential volume declaration: {error}"))?;
    if declarations.is_empty() || declarations.len() > MAX_VOLUMES {
        return Err(anyhow!(
            "confidential volume declaration must contain between 1 and {MAX_VOLUMES} volumes"
        ));
    }

    let mut manifest_uris = BTreeSet::new();
    let mut device_paths = BTreeSet::new();
    let mut container_destinations = BTreeSet::new();
    for (volume_name, declaration) in &declarations {
        validate_dns_label("confidential volume", volume_name)?;
        validate_confidential_manifest_uri(&declaration.manifest_uri)?;
        if !manifest_uris.insert(declaration.manifest_uri.as_str()) {
            return Err(anyhow!(
                "confidential manifest URI {:?} is assigned to more than one volume",
                declaration.manifest_uri
            ));
        }
        if declaration.access != ConfidentialStorageAccess::ReadWrite {
            return Err(anyhow!(
                "confidential volume {volume_name:?} requests unsupported readOnly access"
            ));
        }
        validate_device_path(&declaration.device_path)?;
        if !device_paths.insert(declaration.device_path.as_str()) {
            return Err(anyhow!(
                "confidential device path {:?} is assigned to more than one volume",
                declaration.device_path
            ));
        }
        if declaration.fs_group.is_none() && declaration.fs_group_change_policy.is_some() {
            return Err(anyhow!(
                "confidential volume {volume_name:?} fsGroupChangePolicy requires fsGroup"
            ));
        }
        if declaration.mounts.0.is_empty() {
            return Err(anyhow!(
                "confidential volume {volume_name:?} must name at least one container mount"
            ));
        }
        for (container_name, destinations) in &declaration.mounts.0 {
            validate_dns_label("confidential container", container_name)?;
            if destinations.is_empty() || destinations.len() > MAX_MOUNTS_PER_CONTAINER {
                return Err(anyhow!(
                    "confidential volume {volume_name:?} container {container_name:?} must contain between 1 and {MAX_MOUNTS_PER_CONTAINER} mount destinations"
                ));
            }
            let mut local_destinations = BTreeSet::new();
            for destination in destinations {
                validate_mount_destination(destination)?;
                if !local_destinations.insert(destination.as_str()) {
                    return Err(anyhow!(
                        "confidential volume {volume_name:?} repeats mount destination {destination:?} for container {container_name:?}"
                    ));
                }
                if !container_destinations.insert((container_name.as_str(), destination.as_str())) {
                    return Err(anyhow!(
                        "confidential mount destination {destination:?} for container {container_name:?} is assigned to more than one volume"
                    ));
                }
            }
        }
    }

    Ok(declarations)
}

fn validate_dns_label(kind: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid {
        return Err(anyhow!("{kind} name {value:?} is not a DNS label"));
    }
    Ok(())
}

fn validate_device_path(value: &str) -> Result<()> {
    if !value.starts_with("/dev/") || !is_clean_absolute_path(value) {
        return Err(anyhow!(
            "confidential device path {value:?} must be a clean absolute path beneath /dev"
        ));
    }
    Ok(())
}

fn validate_mount_destination(value: &str) -> Result<()> {
    if value == "/" || !is_clean_absolute_path(value) {
        return Err(anyhow!(
            "confidential mount destination {value:?} must be a clean non-root absolute path"
        ));
    }
    Ok(())
}

fn is_clean_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && !value.contains("//")
        && !value.ends_with('/')
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
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

    #[test]
    fn accepts_exact_backend_neutral_contract() {
        let declarations = parse_confidential_volume_declarations(VALID).unwrap();
        let declaration = declarations.get("workspace").unwrap();
        assert_eq!(declaration.device_path, "/dev/confidential-workspace");
        assert_eq!(declaration.fs_group, Some(1000));
        assert_eq!(
            declaration.fs_group_change_policy,
            Some(ConfidentialFSGroupChangePolicy::OnRootMismatch)
        );
        assert_eq!(
            declaration.mounts.0["workspace"],
            ["/home/workspace", "/workspace"]
        );
    }

    #[test]
    fn rejects_ambiguous_or_mutable_contracts() {
        let invalid = [
            VALID.replace("\"access\": \"readWrite\"", "\"access\": \"readOnly\""),
            VALID.replace("/dev/confidential-workspace", "../dev/workspace"),
            VALID.replace("/home/workspace", "/home/../workspace"),
            VALID.replace(
                "\"fsGroupChangePolicy\": \"OnRootMismatch\",",
                "\"fsGroupChangePolicy\": \"OnRootMismatch\", \"unexpected\": true,",
            ),
            VALID.replace(
                "\"workspace\": {",
                "\"workspace\": {\"manifestUri\": \"kbs:///tenant/storage-manifests/duplicate-v1\", \"access\": \"readWrite\", \"devicePath\": \"/dev/duplicate\", \"mounts\": {\"workspace\": [\"/duplicate\"]}}, \"workspace\": {",
            ),
            VALID.replace(
                "\"dind\": [\"/workspace\"]",
                "\"workspace\": [\"/other\"], \"dind\": [\"/workspace\"]",
            ),
        ];

        for raw in invalid {
            assert!(
                parse_confidential_volume_declarations(&raw).is_err(),
                "unexpectedly accepted {}",
                raw
            );
        }
    }

    #[test]
    fn rejects_destination_collisions_between_volumes() {
        let raw = r#"{
            "first":{"devicePath":"/dev/first","manifestUri":"kbs:///t/m/first","access":"readWrite","mounts":{"workspace":["/data"]}},
            "second":{"devicePath":"/dev/second","manifestUri":"kbs:///t/m/second","access":"readWrite","mounts":{"workspace":["/data"]}}
        }"#;
        assert!(parse_confidential_volume_declarations(raw).is_err());
    }
}
