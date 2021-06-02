use crate::error::Error;
use crate::protocol::{Base64Buffer, Request, Response, WireMessage};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey, NONCEBYTES};

use std::path::PathBuf;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct Pairing {
    pub device_public_key: Base64Buffer,
    pub device_name: String,
    pub aws_push_id: Option<String>,
    pub device_token: Option<String>,
    #[serde(flatten)]
    pub keypair: Keypair,
}

impl Pairing {
    fn path() -> Result<PathBuf, Error> {
        let path = super::create_home_path()?.join("pairing.json");
        Ok(path)
    }

    pub fn load_from_disk() -> Result<Self, Error> {
        let path = Self::path()?;

        if !std::fs::metadata(&path).is_ok() {
            return Err(Error::PairingNotFound);
        }

        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    pub fn store_to_disk(&self) -> Result<(), Error> {
        let path = Self::path()?;
        std::fs::write(&path, serde_json::to_string_pretty(&self)?)?;
        Ok(())
    }

    pub fn queue_uuid(&self) -> Result<Uuid, Error> {
        self.keypair.queue_uuid()
    }

    pub fn device_public_key(&self) -> Result<PublicKey, Error> {
        PublicKey::from_slice(&self.device_public_key.0).ok_or(Error::InvalidPairingKeys)
    }

    pub fn seal(&self, request: &Request) -> Result<WireMessage, Error> {
        self.keypair.seal(self.device_public_key()?, request)
    }

    fn open(&self, wire_message: &WireMessage) -> Result<Response, Error> {
        self.keypair.open(self.device_public_key()?, wire_message)
    }

    pub fn find_response(
        &self,
        request_id: &str,
        wire_messages: &[WireMessage],
    ) -> Result<Option<Response>, Error> {
        for wire_message in wire_messages {
            let response = self.open(wire_message)?;
            if response.request_id.as_str() != request_id {
                continue;
            }
            return Ok(Some(response));
        }
        Ok(None)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PairingQr {
    #[serde(rename = "pk")]
    pub public_key: Base64Buffer,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "v")]
    pub version: String,
    #[serde(flatten)]
    pub os: Os,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Os {
    #[serde(rename = "pk")]
    pub device_identifier: Base64Buffer,
    #[serde(rename = "os")]
    pub kind: String,
    #[serde(rename = "osv")]
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Keypair {
    #[serde(rename = "WorkstationPublicKey")]
    pub public_key: Base64Buffer,
    #[serde(rename = "WorkstationSecretKey")]
    secret_key: Base64Buffer,
}

impl From<(PublicKey, SecretKey)> for Keypair {
    fn from(kp: (PublicKey, SecretKey)) -> Self {
        Self {
            public_key: kp.0 .0.to_vec().into(),
            secret_key: kp.1 .0.to_vec().into(),
        }
    }
}

impl Keypair {
    pub fn queue_uuid(&self) -> Result<Uuid, Error> {
        let hash_prefix = sodiumoxide::crypto::hash::sha256::hash(self.public_key.0.as_slice()).0;
        let uuid = Uuid::from_slice(&hash_prefix[..16])?;
        Ok(uuid)
    }

    fn public_key(&self) -> Result<PublicKey, Error> {
        PublicKey::from_slice(&self.public_key.0).ok_or(Error::InvalidPairingKeys)
    }

    fn secret_key(&self) -> Result<SecretKey, Error> {
        SecretKey::from_slice(&self.secret_key.0).ok_or(Error::InvalidPairingKeys)
    }

    fn seal(&self, device_pk: PublicKey, request: &Request) -> Result<WireMessage, Error> {
        let message = serde_json::to_vec(&request)?;
        let nonce = sodiumoxide::crypto::box_::gen_nonce();
        let ctxt =
            sodiumoxide::crypto::box_::seal(&message, &nonce, &device_pk, &self.secret_key()?);
        Ok(WireMessage::SealedMessage(
            vec![nonce.0.to_vec(), ctxt].concat(),
        ))
    }

    fn open(&self, device_pk: PublicKey, wire_message: &WireMessage) -> Result<Response, Error> {
        let sealed = match wire_message {
            WireMessage::SealedMessage(data) => data.as_slice(),
            _ => return Err(Error::InvalidWireProtocol),
        };

        if sealed.len() < NONCEBYTES {
            return Err(Error::InvalidCiphertext);
        }
        let nonce = sodiumoxide::crypto::box_::Nonce::from_slice(&sealed[0..NONCEBYTES])
            .ok_or(Error::InvalidCiphertext)?;
        let ctxt = &sealed[NONCEBYTES..];
        let plaintext =
            sodiumoxide::crypto::box_::open(ctxt, &nonce, &device_pk, &self.secret_key()?)
                .map_err(|_| Error::UnsealFailed)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn open_sealed_public_key(
        &self,
        wire_message: Option<&WireMessage>,
    ) -> Result<Option<PublicKey>, Error> {
        let sealed = match wire_message {
            None => return Ok(None),
            Some(WireMessage::SealedPublicKey(data)) => data.as_slice(),
            _ => return Err(Error::InvalidWireProtocol),
        };

        let device_public_key =
            sodiumoxide::crypto::sealedbox::open(&sealed, &self.public_key()?, &self.secret_key()?)
                .map_err(|_| Error::UnsealFailed)?;
        Ok(PublicKey::from_slice(&device_public_key))
    }
}
