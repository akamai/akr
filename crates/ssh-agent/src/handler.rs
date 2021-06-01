use crate::protocol::Request;
use crate::protocol::Response;

use crate::error::HandleResult;
use async_trait::async_trait;

#[async_trait]
pub trait SSHAgentHandler: Send + Sync {
    async fn identities(&mut self) -> HandleResult<Response>;
    async fn sign_request(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> HandleResult<Response>;
    async fn add_identity(
        &mut self,
        key_type: String,
        key_contents: Vec<u8>,
    ) -> HandleResult<Response>;

    async fn handle_request(&mut self, request: Request) -> HandleResult<Response> {
        match request {
            Request::RequestIdentities => self.identities().await,
            Request::SignRequest {
                pubkey_blob,
                data,
                flags,
            } => self.sign_request(pubkey_blob, data, flags).await,
            Request::AddIdentity {
                key_type,
                key_contents,
            } => self.add_identity(key_type, key_contents).await,
            Request::Unknown => Ok(Response::Failure),
        }
    }
}
