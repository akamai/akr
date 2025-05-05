use base64::Engine;
use byteorder::{BigEndian, WriteBytesExt};
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};
use ssh_agent::error::HandleResult;
use std::{
    fs::File,
    io::{self, Cursor, Read, Write},
    path::Path,
};

use crate::{
    error::Error,
    prompt::PasswordPrompt,
    protocol::{Base64Buffer, SignFlags},
    util::{read_data, read_string},
};

use ring::{
    rand,
    signature::{self, EcdsaKeyPair},
};

use pem;

/// Represents the key pair of a sk-ecdsa-sha2-nistp256
/// Note the private key is not actually here, because it's hardware backed
/// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SshFido2KeyPairHandle {
    pub application: String,
    pub public_key: Vec<u8>,
    pub key_handle: KeyHandle,
    pub flags: u8,
}

pub type KeyHandle = Vec<u8>;
pub type SshWirePublicKey = Vec<u8>;

impl SshFido2KeyPairHandle {
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
    /// Note: this does't actually coontain the private key
    /// because it's enclave backed...it just contains a "key_handle" (cred id)
    /// in place of the private key
    /// See: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
    #[allow(unused)]
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

        let comment = "AkamaiMFA";
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
        let body = base64::engine::general_purpose::STANDARD
            .encode(data)
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
    pub fn fmt_public_key(&self) -> Result<SshWirePublicKey, std::io::Error> {
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
    pub fn parse_application_from_public_key(fmt_public_key: SshWirePublicKey) -> Result<String, Error> {
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
    /// Note: this does't actually coontain the private key
    /// because it's enclave backed...it just contains a "key_handle" (cred id)
    /// in place of the private key
    /// See: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f

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

/// Represents a fully usable (but possibly locked) SSH key pair.
///
/// We always load public and private key at the same time to ensure consistency.
pub struct SshKey {
    /// The key format identifier. This is the first space-separated part of a `.pub` file.
    ///
    /// Examples: "ssh-dss", "ssh-rsa".
    pub key_type: String,
    /// Key data as a blob.
    ///
    /// This blob is in the same format that RFC4253 "6.6. Public Key Algorithms" specifies, so the
    /// key type is stored in here as well.
    ///
    /// In the `.pub` file, this is stored in Base 64 encoding.
    pub pub_blob: Vec<u8>,
    /// Contents of the private key file
    pub priv_file: Vec<u8>,
    /// Comment associated with the key. The last part of a `.pub` file.
    pub comment: String,
    pub unlocked_key: Option<PrivateKey>,

    /// For ECDSA keys.
    pub ecdsa_key_pair: Option<EcdsaKeyPair>,

    /// General key pair type
    ///
    /// This is a type to make it easy to store different types of key pair in the container.
    /// Each can contain one of the types supported in this crate.
    ///
    /// Key pair is the so-called "private key" which contains both public and private parts of an asymmetry key.
    pub keypair: Option<osshkeys::KeyPair>,
}

impl SshKey {
    /// Reads the public and private part of this key from the file system.
    pub fn from_paths<P1, P2>(pub_path: P1, priv_path: P2) -> io::Result<Self>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let (mut pub_file, mut priv_file) = (File::open(pub_path)?, File::open(priv_path)?);

        let mut pub_content = String::new();
        pub_file.read_to_string(&mut pub_content)?;

        let mut priv_blob = Vec::new();
        priv_file.read_to_end(&mut priv_blob)?;

        let mut splitn = pub_content.splitn(3, ' ');
        let key_type = splitn.next().unwrap().trim().to_string();
        let data_encoded = splitn.next().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "no pubkey data blob found",
        ))?;
        let comment = splitn.next().unwrap_or("").trim().to_string();

        let pub_blob = base64::engine::general_purpose::STANDARD
            .decode(data_encoded.trim())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(SshKey {
            pub_blob,
            priv_file: priv_blob,
            unlocked_key: None,
            key_type,
            comment,
            ecdsa_key_pair: None,
            keypair: None,
        })
    }

    /// Returns the SSH key format identifier (eg. "ssh-rsa").
    #[allow(unused)]
    pub fn format_identifier(&self) -> &str {
        &self.key_type
    }

    /// Returns the key's comment.
    ///
    /// The comment is supposed to be a human readable string that identifies all SSH keys in use.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    pub fn ecdsa_key_pair(&self) -> Option<&EcdsaKeyPair> {
        self.ecdsa_key_pair.as_ref()
    }

    /// Returns the public key blob.
    ///
    /// This blob is used by the SSH-Agent protocol to identify keys. It is stored as a
    /// base64-encoded string after the key type and before the optional comment.
    pub fn pub_key_blob(&self) -> &[u8] {
        &self.pub_blob
    }

    /// Unlocks the private key (if this didn't already happen) using pinentry
    /// and uses the passphrase to create a keypair.
    ///
    /// Returns the keypair which is used for signing and future operations.
    pub fn unlock_ed25519_key(&mut self) -> Result<Option<&osshkeys::KeyPair>, Error> {
        // initialize the password buffer
        let mut password_buffer = [0u8; 128];

        let _ = PasswordPrompt::new(self.comment().to_string()).invoke(&mut password_buffer);

        let password = String::from_utf8(password_buffer.to_vec())?;

        let pass = password.as_str().trim();
        let mut pass1 = String::from("");

        for c in pass.chars() {
            if !c.is_control() && !c.is_whitespace() {
                pass1.push(c);
            }
        }

        let keypair = osshkeys::KeyPair::from_keystr(
            &String::from_utf8_lossy(self.priv_file.as_slice()),
            Some(&pass1),
        )?;

        self.keypair = Some(keypair);

        Ok(self.keypair.as_ref())
    }

    /// Unlocks the private key (if this didn't already happen) using `password_callback` to provide
    /// the key's password, and returns a reference to the private key.
    ///
    /// The key will stay unlocked when this method returns.
    pub fn unlock_with<F>(
        &mut self,
        password_callback: F,
        pubkey_type: String,
    ) -> Result<(&PrivateKey, Option<&EcdsaKeyPair>), Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>,
    {
        if let Some(ref pkey) = self.unlocked_key {
            return Ok((pkey, self.ecdsa_key_pair()));
        }

        let pkey = PKey::private_key_from_pem_callback(&self.priv_file.as_slice(), password_callback)
            .map_err(|e| Error::SslError(e))?;

        let pkcs8_bytes = &pkey.private_key_to_pem_pkcs8()?;
        let pem_bytes = pem::parse(pkcs8_bytes.as_slice()).expect("Could not parse pem key");
        let pkcs8_bytes = pem_bytes.contents().to_vec();

        self.unlocked_key = Some(PrivateKey { pkey });

        if pubkey_type.contains("ecdsa") {
            let key_pair = match pubkey_type.as_str() {
                "ecdsa-sha2-nistp256" => {
                    let rng = rand::SystemRandom::new();
                    let key_pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_slice(), &rng);
                    Some(key_pair.expect("Could not parse pkcs8 key"))
                },
                "ecdsa-sha2-nistp384" => {
                    let rng = rand::SystemRandom::new();
                    let key_pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_slice(), &rng);
                    Some(key_pair.expect("Could not parse pkcs8 key"))
                },
                _ => None,
            };

            self.ecdsa_key_pair = key_pair;
        }

        Ok((
            self.unlocked_key
                .as_ref()
                .expect("Couldn't extract the unlocked key"),
            self.ecdsa_key_pair(),
        ))
    }
}

/// A private SSH key.
pub struct PrivateKey {
    pkey: PKey<Private>,
}

impl PrivateKey {
    /// Signs `data` with this key, according to RFC 4253 "6.6. Public Key Algorithms".
    pub fn sign_rsa(&self, data: &[u8], flags: &u32) -> HandleResult<(Vec<u8>, &str)> {
        assert!(self.pkey.rsa().is_ok(), "only RSA keys are supported");
        let flags = SignFlags::from_bits_truncate(*flags);

        if flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_256)
            && flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_512)
        {
            return Err(Error::IllegalFlags)?;
        }

        let (algo_name, digest_type) = if flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_256) {
            ("rsa-sha2-256", MessageDigest::sha256())
        } else if flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_512) {
            ("rsa-sha2-512", MessageDigest::sha512())
        } else {
            ("ssh-rsa", MessageDigest::sha1())
        };

        let mut signer = Signer::new(digest_type, &self.pkey).map_err(Error::from)?;
        signer.update(data).map_err(Error::from)?;
        let blob = signer.sign_to_vec().map_err(Error::from)?;
        Ok((blob, algo_name))
    }

    pub fn sign_ecdsa(
        &self,
        data: &[u8],
        _flags: &u32,
        key_pair: Option<&EcdsaKeyPair>,
    ) -> HandleResult<Vec<u8>> {
        let rng = rand::SystemRandom::new();
        match key_pair {
            Some(key_pair) => {
                let sig = key_pair
                    .sign(&rng, data)
                    .map_err(|_e| Error::InvalidPairingKeys)?;
                let signature = sig.as_ref().to_vec();
                Ok(signature)
            }
            None => Err(Error::InvalidPairingKeys)?,
        }
    }
}
