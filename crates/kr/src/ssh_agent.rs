use crate::client::Client;
use crate::prompt::PasswordPrompt;
use crate::protocol::{AuthenticateRequest, AuthenticateResponse, Base64Buffer, RequestBody};
use crate::ssh_format::{SshKey, SshWirePublicKey};
use crate::{
    error::*,
    util::{read_data, read_string},
};
use crate::{identity::StoredIdentity, ssh_format::SshFido2KeyPairHandle};
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use eagre_asn1::der::DER;
use eagre_asn1::der_sequence;
use osshkeys::PrivateParts;
use ssh_agent::error::HandleResult;
use ssh_agent::Identity;
use ssh_agent::Response;
use ssh_agent::SSHAgentHandler;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::{
    io::{Cursor, Write},
    vec,
};

#[derive(Debug)]
struct ECDSASign {
    r: Vec<u8>,
    s: Vec<u8>,
}

eagre_asn1::der_sequence! {
    ECDSASign:
        r: NOTAG TYPE Vec<u8>,
        s: NOTAG TYPE Vec<u8>,
}

pub struct Agent {
    pub client: Client,
    identities: HashMap<SshWirePublicKey, SshFido2KeyPairHandle>,
    ssh_keys: Vec<SshKey>,
}

impl Agent {
    pub fn new(client: Client) -> Self {
        Agent {
            client,
            identities: HashMap::new(),
            ssh_keys: Vec::new(),
        }
    }

    pub fn preload_user_keys_from_dir<P: AsRef<Path>>(&mut self, key_dir: P) {
        let key_dir = key_dir.as_ref();
        let key_count_pre = self.ssh_keys.len();

        let read_dir = match fs::read_dir(key_dir) {
            Ok(rd) => rd,
            Err(e) => {
                eprintln!("couldn't read key directory {}: {}", key_dir.display(), e);
                return;
            }
        };

        for entry in read_dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!("couldn't read dir entry: {}", e);
                    continue;
                }
            };

            let path = entry.path();

            // Find all `.pub` files in the directory
            if path.extension() == Some(OsStr::new("pub")) {
                // Only preload if the corresponding non-pub file exists
                let priv_path = path.with_extension("");
                match priv_path.metadata() {
                    Ok(_) => match SshKey::from_paths(&path, priv_path) {
                        Ok(key) => {
                            println!(
                                "successfully preloaded public key '{}' from {}",
                                key.comment(),
                                path.display()
                            );
                            self.ssh_keys.push(key);
                        }
                        Err(e) => {
                            eprintln!("couldn't preload {}: {}", path.display(), e);
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "{} has no associated private key file ({})",
                            path.display(),
                            e
                        );
                    }
                }
            }
        }

        println!(
            "preloaded {} keys from {}",
            self.ssh_keys.len() - key_count_pre,
            key_dir.display()
        );
    }

    async fn sign_fido2(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        _flags: u32,
    ) -> HandleResult<Response> {
        // try to find the matching key handle
        let id = self
            .identities
            .iter()
            .filter(|(pk, _)| pk.as_slice() == pubkey.as_slice())
            .next()
            .map(|id| id.1);
        let rp_id = if let Some(id) = &id {
            id.application.clone()
        } else {
            // parse the rp_id from the public key
            let rp_id = SshFido2KeyPairHandle::parse_application_from_public_key(pubkey)?;
            if !rp_id.starts_with("ssh:") {
                return Err(Error::BadRpPrefix)?;
            }
            rp_id
        };

        //pop a notification
        let rp_id_clone = rp_id.clone();
        tokio::spawn(async move {
            show_notification(&rp_id_clone);
        });

        let challenge_hash = sodiumoxide::crypto::hash::sha256::hash(data.as_slice())
            .0
            .to_vec();

        // get the signature from the client
        let resp: AuthenticateResponse = self
            .client
            .send_request(RequestBody::Authenticate(AuthenticateRequest {
                challenge: Base64Buffer(challenge_hash),
                rp_id,
                extensions: None,
                key_handle: id.map(|id| id.key_handle.clone()).map(Base64Buffer),
                key_handles: None,
            }))
            .await?;

        let flags = resp.get_auth_flags()?;
        /* parse the asn.1 signature into ssh format

           ecdsa signature
               mpint		r
               mpint		s
        */
        let asn1_sig = ECDSASign::der_from_bytes(resp.signature.0)?;
        let mut signature: Vec<u8> = Vec::new();

        signature.write_u32::<BigEndian>(asn1_sig.r.len() as u32)?;
        signature.write_all(asn1_sig.r.as_slice())?;

        signature.write_u32::<BigEndian>(asn1_sig.s.len() as u32)?;
        signature.write_all(asn1_sig.s.as_slice())?;

        /*
           string		"sk-ecdsa-sha2-nistp256@openssh.com"
           string		ecdsa_signature
           byte		    flags
           uint32		counter

           https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
        */
        let mut data: Vec<u8> = vec![];

        const SIG_TYPE_ID: &'static str = "sk-ecdsa-sha2-nistp256@openssh.com";
        data.write_u32::<BigEndian>(SIG_TYPE_ID.len() as u32)?;
        data.write_all(SIG_TYPE_ID.as_bytes())?;

        data.write_u32::<BigEndian>(signature.len() as u32)?;
        data.write_all(&signature)?;

        data.write_u8(flags)?;
        data.write_u32::<BigEndian>(resp.counter)?;

        Ok(Response::SignResponse { signature: data })
    }

    async fn sign_rsa(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        pubkey_type: String,
    ) -> HandleResult<Response> {
        let key = self
            .ssh_keys
            .iter_mut()
            .find(|key| key.pub_key_blob() == pubkey);
        match key {
            Some(key) => {
                let comment = key.comment().to_string();
                let (signature, algo) = {
                    let (priv_key, _ecdsa_key_pair) = match key.unlock_with(
                        |buf| Ok(PasswordPrompt::new(comment).invoke(buf)),
                        pubkey_type,
                    ) {
                        Ok(p) => p,
                        Err(_e) => {
                            return Ok(Response::Failure);
                        }
                    };

                    match priv_key.sign_rsa(&data, &flags) {
                        Ok((signature, algo)) => (signature, algo),
                        Err(_e) => {
                            return Ok(Response::Failure);
                        }
                    }
                };

                Ok(Response::SignResponse2 {
                    algo_name: algo.to_string(),
                    signature,
                })
            }
            None => Ok(Response::Failure),
        }
    }

    async fn sign_ecdsa(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        pubkey_type: String,
    ) -> HandleResult<Response> {
        let key = self
            .ssh_keys
            .iter_mut()
            .find(|key| key.pub_key_blob() == pubkey);
        match key {
            Some(key) => {
                let comment = key.comment().to_string();
                let signature = {
                    let (priv_key, ecdsa_key_pair) = match key.unlock_with(
                        |buf| Ok(PasswordPrompt::new(comment).invoke(buf)),
                        pubkey_type.clone(),
                    ) {
                        Ok(p) => p,
                        Err(_e) => {
                            return Ok(Response::Failure);
                        }
                    };

                    match priv_key.sign_ecdsa(&data, &flags, ecdsa_key_pair) {
                        Ok(signature) => signature,
                        Err(_e) => {
                            return Ok(Response::Failure);
                        }
                    }
                };

                let asn1_sig = ECDSASign::der_from_bytes(signature)?;
                let mut signature: Vec<u8> = Vec::new();

                signature.write_u32::<BigEndian>(asn1_sig.r.len() as u32)?;
                signature.write_all(asn1_sig.r.as_slice())?;

                signature.write_u32::<BigEndian>(asn1_sig.s.len() as u32)?;
                signature.write_all(asn1_sig.s.as_slice())?;

                Ok(Response::SignResponse2 {
                    algo_name: pubkey_type,
                    signature,
                })
            }
            None => Ok(Response::Failure),
        }
    }

    async fn sign_ed25519(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        _flags: u32,
        pubkey_type: String,
    ) -> HandleResult<Response> {
        let key = self
            .ssh_keys
            .iter_mut()
            .find(|key| key.pub_key_blob() == pubkey);
        match key {
            Some(key) => match &key.keypair {
                Some(keypair) => {
                    let signature = keypair.sign(&data.as_slice()).unwrap();

                    Ok(Response::SignResponse2 {
                        algo_name: pubkey_type,
                        signature,
                    })
                }
                None => {
                    let keypair = key.unlock_ed25519_key()?;

                    match keypair {
                        Some(kp) => {
                            let signature = kp.sign(&data.as_slice()).unwrap();

                            Ok(Response::SignResponse2 {
                                algo_name: pubkey_type,
                                signature,
                            })
                        }
                        None => {
                            return Ok(Response::Failure);
                        }
                    }
                }
            },
            None => Ok(Response::Failure),
        }
    }
}

#[async_trait]
impl SSHAgentHandler for Agent {
    async fn identities(&mut self) -> HandleResult<Response> {
        let ids = StoredIdentity::load_from_disk()?.key_pair_handles;
        self.identities = ids
            .into_iter()
            .map(|kp| Ok((kp.fmt_public_key()?, kp)))
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .collect();

        let mut identities = self
            .identities
            .iter()
            .map(|(pubkey, kp)| {
                Ok(Identity {
                    key_comment: kp.application.clone(),
                    key_blob: pubkey.clone(),
                })
            })
            .collect::<Result<Vec<Identity>, Error>>()?;

        let keys = self
            .ssh_keys
            .iter()
            .map(|key| {
                Ok(Identity {
                    key_comment: key.comment().to_string(),
                    key_blob: key.pub_key_blob().to_vec(),
                })
            })
            .collect::<Result<Vec<Identity>, Error>>()?;

        // push keys to ids
        identities.extend(keys);

        let ids = identities
            .iter()
            .map(|id| {
                Ok(Identity {
                    key_comment: id.key_comment.clone(),
                    key_blob: id.key_blob.clone(),
                })
            })
            .collect::<Result<Vec<Identity>, Error>>()
            .map(Response::Identities)?;

        Ok(ids)
    }

    async fn add_identity(
        &mut self,
        key_type: String,
        key_blob: Vec<u8>,
    ) -> HandleResult<Response> {
        if key_type.as_str() != SshFido2KeyPairHandle::TYPE_ID {
            eprintln!("add error: not a fido2 ssh keypair");
            return Ok(Response::Success);
        }
        /*
           string		curve name
           ec_point	Q
           string		application (user-specified, but typically "ssh:")
           uint8		flags
           string		key_handle
           string		reserved
        */
        let mut cursor = Cursor::new(key_blob);
        let _curve_name = read_string(&mut cursor)?;
        let public_key = read_data(&mut cursor)?;
        let application = read_string(&mut cursor)?;
        let flags = cursor.read_u8()?;
        let key_handle = read_data(&mut cursor)?;

        let identity = SshFido2KeyPairHandle {
            application,
            key_handle,
            public_key,
            flags,
        };
        self.identities.insert(identity.fmt_public_key()?, identity);

        Ok(Response::Success)
    }

    async fn sign_request(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> HandleResult<Response> {
        /* data:
         Packet Format (SSH_MSG_USERAUTH_REQUEST):
         string    session identifier
         byte      SSH_MSG_USERAUTH_REQUEST
         string    user name
         string    service name
         string    "publickey"
         boolean   TRUE
         string    public key algorithm name
         string    public key to be used for authentication
        */

        let mut cursor = Cursor::new(pubkey.clone());
        let pubkey_type = read_string(&mut cursor)?;

        if pubkey_type == "sk-ecdsa-sha2-nistp256@openssh.com".to_string() {
            self.sign_fido2(pubkey, data, flags).await
        } else if pubkey_type.contains("ssh-rsa") {
            self.sign_rsa(pubkey, data, flags, pubkey_type).await
        } else if pubkey_type.contains("ecdsa") {
            self.sign_ecdsa(pubkey, data, flags, pubkey_type).await
        } else if pubkey_type.contains("ed25519") {
            self.sign_ed25519(pubkey, data, flags, pubkey_type).await
        } else {
            Ok(Response::Failure)
        }
    }
}

/// show a desktop notification about the pending request
fn show_notification(rp_id: &str) {
    #[cfg(target_os = "macos")]
    //open issue https://github.com/h4llow3En/mac-notification-sys/issues/8
    // let _ = mac_notification_sys::set_application(&"com.akamai.mfa");
    let _ = notify_rust::Notification::new()
        .summary(format!("Login Request: {}", rp_id).as_str())
        .show();
}
