use crate::error::Error;
use crate::protocol::Base64Buffer;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredIdentity {
    #[serde(rename = "device_id")]
    pub device_id: Option<Base64Buffer>,
}

const ID_FILE: &'static str = "me";

impl StoredIdentity {
    fn path() -> Result<PathBuf, Error> {
        let dirs = directories::UserDirs::new().ok_or(Error::PairingNotFound)?;
        let path = format!(
            "{}{}{}",
            dirs.home_dir().display(),
            crate::HOME_DIR,
            ID_FILE
        );
        Ok(Path::new(path.as_str()).to_path_buf())
    }

    pub fn load_from_disk() -> Result<Self, Error> {
        let path = Self::path()?;

        if !std::fs::metadata(&path).is_ok() {
            return Err(Error::StoredIdentityNotFound);
        }

        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    pub fn store_to_disk(&self) -> Result<(), Error> {
        let path = Self::path()?;
        std::fs::write(&path, serde_json::to_string_pretty(&self)?)?;
        Ok(())
    }
}
