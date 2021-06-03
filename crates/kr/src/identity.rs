use crate::error::Error;
use crate::protocol::Base64Buffer;
use crate::ssh_format::SshFido2KeyPairHandle;
use serde::{Deserialize, Serialize};
use sodiumoxide::hex;
use std::path::PathBuf;

#[derive(Debug)]
pub struct StoredIdentity {
    pub device_id: Option<Base64Buffer>,
    pub key_pair_handles: Vec<SshFido2KeyPairHandle>,
}

#[derive(Serialize, Deserialize, Debug)]
struct StoredId {
    pub device_id: Option<Base64Buffer>,
}

impl StoredIdentity {
    const ID_FILE: &'static str = "id";
    const PUBLIC_KEYS_DIR: &'static str = "pub";

    fn dir_path() -> Result<PathBuf, Error> {
        let dirs = directories::UserDirs::new().ok_or(Error::PairingNotFound)?;
        Ok(dirs.home_dir().join(crate::HOME_DIR))
    }

    fn id_path() -> Result<PathBuf, Error> {
        Ok(Self::dir_path()?.join(Self::ID_FILE))
    }

    fn pub_keys_dir_path() -> Result<PathBuf, Error> {
        Ok(Self::dir_path()?.join(Self::PUBLIC_KEYS_DIR))
    }

    pub fn store_key_pair_handle(handle: &SshFido2KeyPairHandle) -> Result<(), Error> {
        // filter out keys for other purposes
        if !handle.application.starts_with("ssh:") {
            return Ok(());
        }

        let dir_path = Self::pub_keys_dir_path()?;
        if !dir_path.exists() {
            std::fs::create_dir_all(&dir_path)?;
        }

        let name = hex::encode(
            sodiumoxide::crypto::hash::sha256::hash(handle.key_handle.as_slice()).as_ref(),
        );
        let path = dir_path.join(&name);
        std::fs::write(path, serde_json::to_vec(handle)?)?;
        Ok(())
    }

    pub fn clear_stored_key_handles() -> Result<(), Error> {
        if Self::pub_keys_dir_path()?.exists() {
            let _ = std::fs::remove_dir_all(Self::pub_keys_dir_path()?)?;
        }

        Ok(())
    }

    pub fn load_from_disk() -> Result<Self, Error> {
        let path = Self::id_path()?;

        if !std::fs::metadata(&path).is_ok() {
            return Err(Error::StoredIdentityNotFound);
        }

        let contents = std::fs::read_to_string(path)?;
        let id: StoredId = serde_json::from_str(&contents)?;

        let key_pair_handles = if let Ok(dir) = std::fs::read_dir(Self::pub_keys_dir_path()?) {
            dir.into_iter()
                .map(|entry| {
                    let path: PathBuf = entry.ok()?.path();
                    if path.is_dir() {
                        return None;
                    }
                    let contents = std::fs::read_to_string(path).ok()?;
                    let kp: SshFido2KeyPairHandle = serde_json::from_str(&contents).ok()?;
                    Some(kp)
                })
                .filter_map(std::convert::identity)
                .collect()
        } else {
            vec![]
        };

        Ok(StoredIdentity {
            device_id: id.device_id,
            key_pair_handles,
        })
    }

    pub fn store_to_disk(&self) -> Result<(), Error> {
        let path = Self::id_path()?;
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&StoredId {
                device_id: self.device_id.clone(),
            })?,
        )?;

        Self::clear_stored_key_handles()?;

        self.key_pair_handles
            .iter()
            .map(Self::store_key_pair_handle)
            .collect::<Result<(), Error>>()?;
        Ok(())
    }
}
