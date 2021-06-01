use byteorder::{BigEndian, WriteBytesExt};
use pem::EncodeConfig;
use std::io::{Cursor, Write};

use crate::{
    error::Error,
    protocol::Base64Buffer,
    util::{read_data, read_string},
};

/// Represents the key pair of a sk-ecdsa-sha2-nistp256
/// Note the private key is not actually here, because it's hardware backed
/// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
pub struct SshFido2KeyPair {
    pub application: String,
    pub public_key: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub flags: u8,
}

impl SshFido2KeyPair {
    pub const TYPE_ID: &'static str = "sk-ecdsa-sha2-nistp256@openssh.com";
    const CURVE_NAME: &'static str = "nistp256";

    /// Public Key file format
    pub fn authorized_public_key(&self) -> Result<String, Error> {
        let wire = self.fmt_public_key()?;
        Ok(format!(
            "{} {} {}",
            Self::TYPE_ID,
            Base64Buffer(wire).to_string(),
            &self.application
        ))
    }

    /// Private key PEM format
    pub fn private_key_pem(&self) -> Result<String, Error> {
        /*
        "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
        32-bit length, "none"   # ciphername length and string
        32-bit length, "none"   # kdfname length and string
        32-bit length, nil      # kdf (0 length, no kdf)
        32-bit 0x01             # number of keys, hard-coded to 1 (no length)
        32-bit length, sshpub   # public key in ssh format
            32-bit length, keytype
            32-bit length, pub0
            32-bit length, pub1
        32-bit length for rnd+prv+comment+pad
            64-bit dummy checksum?  # a random 32-bit int, repeated
            32-bit length, keytype  # the private key (including public)
            32-bit length, pub0     # Public Key parts
            32-bit length, pub1
            32-bit length, prv0     # Private Key parts
            ...                     # (number varies by type)
            32-bit length, comment  # comment string
            padding bytes 0x010203  # pad to blocksize (see notes below)
         */

        let mut data = vec![];
        data.write_all(b"openssh-key-v1\0")?;

        data.write_u32::<BigEndian>(4)?;
        data.write_all(b"none")?;
        data.write_u32::<BigEndian>(4)?;
        data.write_all(b"none")?;
        data.write_u32::<BigEndian>(0)?;

        data.write_u32::<BigEndian>(1)?;

        let pub_key = self.fmt_public_key()?;
        data.write_u32::<BigEndian>(pub_key.len() as u32)?;
        data.write_all(&pub_key)?;

        let comment = "test";
        let dummy_checksum = sodiumoxide::randombytes::randombytes(4);
        let priv_key = self.fmt_private_key()?;
        let len = (dummy_checksum.len() * 2) + priv_key.len() + 4 + comment.len();
        let pad_bytes = if len % 8 == 0 { 0 } else { 8 - (len % 8) };
        let pad = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        data.write_u32::<BigEndian>((len + pad_bytes) as u32)?;
        data.write_all(&dummy_checksum)?;
        data.write_all(&dummy_checksum)?;
        data.write_all(&priv_key)?;

        data.write_u32::<BigEndian>(comment.len() as u32)?;
        data.write_all(comment.as_bytes())?;

        data.write_all(&pad[0..pad_bytes])?;

        // write the acii armor
        let body = base64::encode(data)
            .chars()
            .collect::<Vec<char>>()
            .chunks(70)
            .map(|line| line.iter().collect::<String>())
            .map(|s| format!("{}\n", s))
            .collect::<String>();

        let head = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let tail = "-----END OPENSSH PRIVATE KEY-----";

        Ok(format!("{}\n{}{}\n", head, body, tail))
    }

    /// Format an SSH Public key
    ///
    ///    string		"sk-ecdsa-sha2-nistp256@openssh.com"
    ///    string		curve name
    ///    ec_point	    Q
    ///    string		application (user-specified, but typically "ssh:")    
    ///
    pub fn fmt_public_key(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut data = vec![];

        data.write_u32::<BigEndian>(Self::TYPE_ID.len() as u32)?;
        data.write_all(Self::TYPE_ID.as_bytes())?;

        data.write_u32::<BigEndian>(Self::CURVE_NAME.len() as u32)?;
        data.write_all(Self::CURVE_NAME.as_bytes())?;

        data.write_u32::<BigEndian>(self.public_key.len() as u32)?;
        data.write_all(self.public_key.as_slice())?;

        data.write_u32::<BigEndian>(self.application.len() as u32)?;
        data.write_all(self.application.as_bytes())?;

        Ok(data)
    }

    /// extract the "application" string (rp id) from a wire format public key
    pub fn parse_application_from_public_key(fmt_public_key: Vec<u8>) -> Result<String, Error> {
        let mut buf = Cursor::new(fmt_public_key);
        let _type = read_data(&mut buf)?;
        let _curve = read_data(&mut buf)?;
        let _pub = read_data(&mut buf)?;
        let app = read_string(&mut buf)?;
        Ok(app)
    }

    /// Format an SSH Private key
    ///    string		"sk-ecdsa-sha2-nistp256@openssh.com"
    ///    string		curve name
    ///    ec_point	Q
    ///    string		application (user-specified, but typically "ssh:")
    ///    uint8		flags
    ///    string		key_handle
    ///    string		reserved
    ///
    pub fn fmt_private_key(&self) -> Result<Vec<u8>, Error> {
        let mut data = vec![];

        data.write_u32::<BigEndian>(Self::TYPE_ID.len() as u32)?;
        data.write_all(Self::TYPE_ID.as_bytes())?;

        data.write_u32::<BigEndian>(Self::CURVE_NAME.len() as u32)?;
        data.write_all(Self::CURVE_NAME.as_bytes())?;

        data.write_u32::<BigEndian>(self.public_key.len() as u32)?;
        data.write_all(self.public_key.as_slice())?;

        data.write_u32::<BigEndian>(self.application.len() as u32)?;
        data.write_all(self.application.as_bytes())?;

        data.write_u8(self.flags)?;

        data.write_u32::<BigEndian>(self.key_handle.len() as u32)?;
        data.write_all(self.key_handle.as_slice())?;

        data.write_u32::<BigEndian>(0)?;

        Ok(data)
    }
}
