use crate::protocol::Request;
use crate::protocol::Response;

use crate::error::HandleResult;
use async_trait::async_trait;

#[async_trait]
pub trait SSHAgentHandler: Send + Sync {
    async fn identities(&mut self) -> HandleResult<Response>;
    async fn sign_request(
        &mut self,
        request: crate::protocol::SignRequest,
    ) -> HandleResult<Response>;
    async fn add_identity(
        &mut self,
        key_type: String,
        key_contents: Vec<u8>,
    ) -> HandleResult<Response>;

    async fn handle_request(&mut self, request: Request) -> HandleResult<Response> {
        // print request
        eprintln!("handle_request: {:?}", request);
        let response = match request {
            Request::RequestIdentities => {
                let data = self.identities().await.unwrap();
                Ok(data)
            }
            Request::SignRequest(request) => self.sign_request(request).await,
            Request::AddIdentity {
                key_type,
                key_contents,
            } => self.add_identity(key_type, key_contents).await,
            Request::Unknown => Ok(Response::Failure),
        };

        // print response
        eprintln!("response: {:?}", response);

        response
    }
}
