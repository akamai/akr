use crate::protocol::{Base64Buffer, RequestBody};
use crate::{client::Client, transport::Transport};
use crate::{
    error::*,
    util::{read_data, read_string},
};
use crate::{identity::StoredIdentity, ssh_format::SshFido2KeyPair};
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use eagre_asn1::der::DER;
use eagre_asn1::der_sequence;
use ssh_agent::error::HandleResult;
use ssh_agent::Identity;
use ssh_agent::Response;
use ssh_agent::SSHAgentHandler;
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

pub struct Agent<T> {
    pub client: Client<T>,
    identities: Vec<Identity>,
}

impl<T> Agent<T> {
    pub fn new(client: Client<T>) -> Self {
        Agent {
            client,
            identities: vec![],
        }
    }
}

// impl<T> Agent<T>
// where
//     T: Transport,
// {
//     async fn get_signature(
//         &mut self,
//         pubkey: Vec<u8>,
//         data: Vec<u8>,
//         host_auth: Vec<u8>,
//         _flags: u32,
//     ) -> Result<Vec<u8>, Error> {
//         let id = StoredIdentity::load_from_disk()?;

//         if id.ssh_public_key_wire.0.as_slice() == pubkey.as_slice() {
//             let short_len = data.len() - pubkey.len() - 4;
//             let short_data = data[..short_len].to_vec();

//             let request = RequestBody::Sign(SignRequest {
//                 data: Base64Buffer(short_data),
//                 host_auth: Base64Buffer(host_auth),
//                 public_key_fingerprint: Base64Buffer(
//                     sodiumoxide::crypto::hash::sha256::hash(&pubkey).0.to_vec(),
//                 ),
//             });

//             let response: SignResponse = self.client.send_request(request).await?;
//             return Ok(response.signature.0);
//         } else {
//             for key in id
//                 .key_op_list
//                 .unwrap_or(KeyOpList {
//                     public_keys: vec![],
//                 })
//                 .public_keys
//             {
//                 if pubkey.as_slice() != key.to_ssh_wire()?.as_slice() {
//                     continue;
//                 }

//                 let request = RequestBody::KeyOp(KeyOpRequest {
//                     data: data.into(),
//                     key_id: key.key_id,
//                     op: crate::protocol::KeyOp::Sign,
//                 });

//                 let response: KeyOpResponse = self.client.send_request(request).await?;

//                 let asn1_sig = ECDSASign::der_from_bytes(response.result.0)?;
//                 //sign that we would return
//                 let mut signature: Vec<u8> = Vec::new();
//                 //write signR
//                 signature.write_u32::<BigEndian>(asn1_sig.r.len() as u32)?;
//                 signature.write_all(asn1_sig.r.as_slice())?;
//                 //write signS
//                 signature.write_u32::<BigEndian>(asn1_sig.s.len() as u32)?;
//                 signature.write_all(asn1_sig.s.as_slice())?;

//                 return Ok(signature);
//             }
//         }

//         Err(Error::UnknownKey)
//     }
// }
#[async_trait]
impl<T> SSHAgentHandler for Agent<T>
where
    T: Transport + Send + Sync,
{
    async fn identities(&mut self) -> HandleResult<Response> {
        Ok(Response::Identities(self.identities.clone()))
    }

    async fn add_identity(
        &mut self,
        key_type: String,
        key_blob: Vec<u8>,
    ) -> HandleResult<Response> {
        if key_type.as_str() != SshFido2KeyPair::TYPE_ID {
            return Err(format!("key type not supported: {}", &key_type))?;
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

        let identity = SshFido2KeyPair {
            application,
            key_handle,
            public_key,
            flags,
        };
        let key_blob = identity.fmt_public_key()?;

        self.identities.push(Identity {
            key_blob,
            key_comment: String::default(),
        });

        Ok(Response::Success)
    }

    async fn sign_request(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> HandleResult<Response> {
        /*
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

        let mut cursor = Cursor::new(data.clone());
        let _session_id = read_data(&mut cursor)?;
        let _req_id = cursor.read_u8()?;
        let _user = read_string(&mut cursor)?;
        let _service = read_string(&mut cursor)?;
        let _ = read_string(&mut cursor);
        let _ = cursor.read_u8()?;
        let _alg_name = read_string(&mut cursor)?;
        let _pubkey = read_data(&mut cursor)?;

        // Ok(Response::SignResponse {
        //     algo_name: String::from("ecdsa-sha2-nistp256"),
        //     signature,
        // })

        dbg!(data);
        dbg!(pubkey);
        dbg!(flags);
        unimplemented!()
    }
}
