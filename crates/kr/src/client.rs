use crate::error::{QueueDenyError, QueueDenyExplanation, QueueEvaluation};
use crate::pairing::Pairing;
use crate::protocol::{Request, RequestBody, ResponseBody, WireMessage};
use crate::transport::Transport;
use crate::{error::Error, transport};
use std::convert::TryFrom;
use transport::queue::QueueClient;
use uuid::Uuid;

pub struct Client {
    queue_client: QueueClient,
}

impl Client {
    pub fn new() -> Result<Client, Error> {
        Ok(Client {
            queue_client: QueueClient::new(),
        })
    }

    pub fn pairing() -> Result<Pairing, Error> {
        Ok(Pairing::load_from_disk()?)
    }
}

impl Client {
    pub async fn send(
        &self,
        device_token: Option<String>,
        queue_uuid: Uuid,
        message: WireMessage,
    ) -> Result<(), Error> {
        let result = self.queue_client.send(device_token, queue_uuid, message.clone()).await;
        if result.is_err() {
            return result;
        }
        Ok(())
    }

    pub async fn receive<T, F>(&self, queue_uuid: Uuid, on_messages: F) -> Result<T, Error>
    where
        F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send + Copy,
    {
        let result = self.queue_client.receive(queue_uuid, on_messages).await?;
        Ok(result)
    }

    pub async fn send_request<R>(&self, request: RequestBody) -> Result<R, Error>
    where
        R: TryFrom<ResponseBody>,
        Error: From<R::Error>,
    {
        let mut pairing = Self::pairing()?;
        let queue_uuid = pairing.queue_uuid()?;
        let request = Request::new(request);
        let wire_message = pairing.seal(&request)?;

        self.send(pairing.device_token.clone(), queue_uuid, wire_message)
            .await?;

        let response = self
            .receive(queue_uuid, |messages| {
                pairing.find_response(&request.id, messages)
            })
            .await?;

        pairing.device_token = response.device_token.or(pairing.device_token);
        pairing.store_to_disk()?;

        Ok(std::convert::TryFrom::try_from(response.body)?)
    }

    pub async fn health_check(&self) -> Result<QueueEvaluation, Error> {
        match self.queue_client.health_check().await {
            Ok(_) => Ok(QueueEvaluation::Allow),
            Err(_) => Ok(QueueEvaluation::Deny(QueueDenyError {
                explanation: QueueDenyExplanation::QueueDown,
            })),
        }
    }
}
