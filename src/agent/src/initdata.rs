//! # Initdata Module
//!
//! This module will do the following things if a proper initdata device with initdata exists.
//! 1. Parse the initdata block device and extract the config files to [`INITDATA_PATH`].
//! 2. Return the initdata and the policy (if any).

// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::OnceLock;
#[cfg(feature = "init-data")]
use std::{os::unix::fs::FileTypeExt, path::Path};

use anyhow::{bail, Context, Result};
use async_compression::tokio::bufread::GzipDecoder;
use base64::{engine::general_purpose::STANDARD, Engine};
use const_format::concatcp;
use kata_types::initdata::InitData;
use sha2::{Digest, Sha256, Sha384, Sha512};
use slog::Logger;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// This is the target directory to store the extracted initdata.
pub const INITDATA_PATH: &str = "/run/confidential-containers/initdata";

const AA_CONFIG_KEY: &str = "aa.toml";
const CDH_CONFIG_KEY: &str = "cdh.toml";
const POLICY_KEY: &str = "policy.rego";
pub(crate) const WORKSPACE_STORAGE_KEY_ID_CLAIM: &str = "codewire_workspace_storage_key_id";

static WORKSPACE_STORAGE_KEY_ID: OnceLock<String> = OnceLock::new();

pub(crate) fn workspace_storage_key_id() -> Option<&'static str> {
    WORKSPACE_STORAGE_KEY_ID.get().map(String::as_str)
}

pub(crate) fn is_canonical_uuid(value: &str) -> bool {
    const GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];
    let groups = value.split('-').collect::<Vec<_>>();
    groups.len() == GROUP_LENGTHS.len()
        && groups
            .iter()
            .zip(GROUP_LENGTHS)
            .all(|(group, expected_len)| {
                group.len() == expected_len
                    && group
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn workspace_storage_key_id_from_initdata(initdata: &InitData) -> Result<Option<String>> {
    let Some(key_id) = initdata.get_coco_data(WORKSPACE_STORAGE_KEY_ID_CLAIM) else {
        return Ok(None);
    };
    if !is_canonical_uuid(key_id) {
        bail!("invalid confidential storage key ID claim");
    }
    Ok(Some(key_id.clone()))
}

/// The path of initdata toml
pub const INITDATA_TOML_PATH: &str = concatcp!(INITDATA_PATH, "/initdata.toml");

/// The path of AA's config file
pub const AA_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/aa.toml");

/// The path of CDH's config file
pub const CDH_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/cdh.toml");

/// Magic number of initdata device
#[cfg(feature = "init-data")]
pub const INITDATA_MAGIC_NUMBER: &[u8] = b"initdata";

/// initdata device with disk type 'vd*'
#[cfg(feature = "init-data")]
const INITDATA_PREFIX_DISK_VDX: &str = "vd";

/// initdata device with disk type 'sd*'
#[cfg(feature = "init-data")]
const INITDATA_PREFIX_DISK_SDX: &str = "sd";

#[cfg(not(feature = "init-data"))]
async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    debug!(logger, "Initdata is disabled");
    Ok(None)
}

#[cfg(feature = "init-data")]
async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    let dev_dir = Path::new("/dev");
    let mut read_dir = tokio::fs::read_dir(dev_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        debug!(logger, "Initdata check device `{filename}`");

        // Currently there're two disk types supported:
        // virtio-blk (vd*) and virtio-scsi (sd*)
        if !filename.starts_with(INITDATA_PREFIX_DISK_VDX)
            && !filename.starts_with(INITDATA_PREFIX_DISK_SDX)
        {
            continue;
        }

        let path = entry.path();

        debug!(logger, "Initdata find potential device: `{path:?}`");
        let metadata = std::fs::metadata(path.clone())?;
        if !metadata.file_type().is_block_device() {
            continue;
        }

        let mut file = tokio::fs::File::open(&path).await?;
        let mut magic = [0; 8];
        match file.read_exact(&mut magic).await {
            Ok(_) => {
                debug!(
                    logger,
                    "Initdata read device `{filename}` first 8 bytes: {magic:?}"
                );
                if magic == INITDATA_MAGIC_NUMBER {
                    let path = path.as_path().to_string_lossy().to_string();
                    debug!(logger, "Found initdata device {path}");
                    return Ok(Some(path));
                }
            }
            Err(e) => debug!(logger, "Initdata read device `{filename}` failed: {e:?}"),
        }
    }

    Ok(None)
}

pub async fn read_initdata(device_path: &str) -> Result<Vec<u8>> {
    let initdata_devfile = tokio::fs::File::open(device_path).await?;
    let mut buf_reader = tokio::io::BufReader::new(initdata_devfile);
    // skip the magic number "initdata"
    buf_reader.seek(std::io::SeekFrom::Start(8)).await?;

    let mut len_buf = [0u8; 8];
    buf_reader.read_exact(&mut len_buf).await?;
    let length = u64::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0; length];
    buf_reader.read_exact(&mut buf).await?;
    let mut gzip_decoder = GzipDecoder::new(&buf[..]);

    let mut initdata = Vec::new();
    let _ = gzip_decoder.read_to_end(&mut initdata).await?;
    Ok(initdata)
}

pub struct InitdataReturnValue {
    pub _digest: Vec<u8>,
    pub _policy: Option<String>,
}

pub async fn initialize_initdata(logger: &Logger) -> Result<Option<InitdataReturnValue>> {
    let logger = logger.new(o!("subsystem" => "initdata"));
    let Some(initdata_device) = detect_initdata_device(&logger).await? else {
        info!(
            logger,
            "Initdata device not found, skip initdata initialization"
        );
        return Ok(None);
    };

    tokio::fs::create_dir_all(INITDATA_PATH)
        .await
        .inspect_err(|e| error!(logger, "Failed to create initdata dir: {e:?}"))?;

    let initdata_content = read_initdata(&initdata_device)
        .await
        .inspect_err(|e| error!(logger, "Failed to read initdata: {e:?}"))?;

    let initdata: InitData =
        toml::from_slice(&initdata_content).context("parse initdata failed")?;
    info!(logger, "Initdata version: {}", initdata.version());
    initdata.validate()?;

    if let Some(key_id) = workspace_storage_key_id_from_initdata(&initdata)? {
        WORKSPACE_STORAGE_KEY_ID
            .set(key_id)
            .map_err(|_| anyhow::anyhow!("confidential storage key ID claim initialized twice"))?;
    }

    tokio::fs::write(INITDATA_TOML_PATH, &initdata_content)
        .await
        .context("write initdata toml failed")?;

    let _digest = match initdata.algorithm() {
        "sha256" => Sha256::digest(&initdata_content).to_vec(),
        "sha384" => Sha384::digest(&initdata_content).to_vec(),
        "sha512" => Sha512::digest(&initdata_content).to_vec(),
        others => bail!("Unsupported hash algorithm {others}"),
    };

    if let Some(config) = initdata.get_coco_data(AA_CONFIG_KEY) {
        tokio::fs::write(AA_CONFIG_PATH, config)
            .await
            .context("write aa config failed")?;
        info!(logger, "write AA config from initdata");
    }

    if let Some(config) = initdata.get_coco_data(CDH_CONFIG_KEY) {
        tokio::fs::write(CDH_CONFIG_PATH, config)
            .await
            .context("write cdh config failed")?;
        info!(logger, "write CDH config from initdata");
    }

    debug!(logger, "Initdata digest: {}", STANDARD.encode(&_digest));

    let res = InitdataReturnValue {
        _digest,
        _policy: initdata.get_coco_data(POLICY_KEY).cloned(),
    };

    Ok(Some(res))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITDATA_IMG_PATH: &str = "testdata/initdata.img";
    const INITDATA_PLAINTEXT: &[u8] = b"some content";

    #[tokio::test]
    async fn parse_initdata() {
        let initdata = read_initdata(INITDATA_IMG_PATH).await.unwrap();
        assert_eq!(initdata, INITDATA_PLAINTEXT);
    }

    #[test]
    fn extracts_canonical_workspace_storage_key_id() {
        let mut initdata = InitData::new("sha384", "0.1.0");
        initdata.insert_data(
            WORKSPACE_STORAGE_KEY_ID_CLAIM,
            "01981234-5678-7abc-8def-0123456789ab",
        );

        assert_eq!(
            workspace_storage_key_id_from_initdata(&initdata).unwrap(),
            Some("01981234-5678-7abc-8def-0123456789ab".to_string())
        );
    }

    #[test]
    fn rejects_noncanonical_workspace_storage_key_id() {
        for key_id in [
            "01981234-5678-7ABC-8def-0123456789ab",
            "not-a-uuid",
            "0198123456787abc8def0123456789ab",
        ] {
            let mut initdata = InitData::new("sha384", "0.1.0");
            initdata.insert_data(WORKSPACE_STORAGE_KEY_ID_CLAIM, key_id);

            assert!(workspace_storage_key_id_from_initdata(&initdata).is_err());
        }
    }
}
