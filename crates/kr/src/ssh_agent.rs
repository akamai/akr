use crate::client::Client;
use crate::protocol::{AuthenticateRequest, AuthenticateResponse, Base64Buffer, RequestBody};
use crate::ssh_format::SshWirePublicKey;
use crate::{
    error::*,
    util::{read_data, read_string},
};
use crate::{identity::StoredIdentity, ssh_format::SshFido2KeyPairHandle};
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use eagre_asn1::der::DER;
use eagre_asn1::der_sequence;
use ssh_agent::error::HandleResult;
use ssh_agent::Identity;
use ssh_agent::Response;
use ssh_agent::SSHAgentHandler;
use std::collections::HashMap;
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
}

impl Agent {
    pub fn new(client: Client) -> Self {
        Agent {
            client,
            identities: HashMap::new(),
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

        let ids = self
            .identities
            .iter()
            .map(|(pubkey, kp)| {
                Ok(Identity {
                    key_comment: kp.application.clone(),
                    key_blob: pubkey.clone(),
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
        _flags: u32,
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

        // try to find the matching key handle
        let id = self
            .identities
            .iter()
            .filter(|(pk, _)| pk.as_slice() == pubkey.as_slice())
            .next()
            .map(|id| id.1);

        let rp_id = if let Some(ref id) = &id {
            id.application.clone()
        } else {
            // parse the rp_id from the public key
            SshFido2KeyPairHandle::parse_application_from_public_key(pubkey)?
        };

        // pop a notification
        show_notification(&rp_id);

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
}

/// show a desktop notification about the pending request
fn show_notification(rp_id: &str) {
    #[cfg(target_os = "macos")]
    let _ = mac_notification_sys::set_application(&"com.akamai.pushzero");

    let _ = notify_rust::Notification::new()
        .summary(format!("Login Request: {}", rp_id).as_str())
        .show();
}
