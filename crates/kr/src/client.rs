use crate::pairing::Pairing;
use crate::protocol::{Request, RequestBody, ResponseBody};
use crate::transport::Transport;
use crate::{error::Error, transport};
use std::convert::TryFrom;
use transport::pzqueue::PZQueueClient;

pub struct Client<T> {
    pub transport: T,
}

pub fn new_default_client() -> Result<Client<PZQueueClient>, Error> {
    Ok(Client {
        transport: PZQueueClient::new(),
    })
}

impl<T> Client<T> {
    fn pairing() -> Result<Pairing, Error> {
        Ok(Pairing::load_from_disk()?)
    }
}

impl<T> Client<T>
where
    T: Transport,
{
    pub async fn send_request<R>(&self, request: RequestBody) -> Result<R, Error>
    where
        R: TryFrom<ResponseBody>,
        Error: From<R::Error>,
    {
        let mut pairing = Self::pairing()?;
        let queue_uuid = pairing.queue_uuid()?;

        let request = Request::new(request);
        let wire_message = pairing.seal(&request)?;
        self.transport
            .send(pairing.device_token.clone(), queue_uuid, wire_message)
            .await?;

        let response = self
            .transport
            .receive(queue_uuid, |messages| {
                pairing.find_response(&request.id, messages)
            })
            .await?;

        pairing.aws_push_id = response.aws_push_id.or(pairing.aws_push_id);
        pairing.device_token = response.device_token.or(pairing.device_token);
        pairing.store_to_disk()?;

        Ok(std::convert::TryFrom::try_from(response.body)?)
    }
}
