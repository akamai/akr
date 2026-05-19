use crate::{
    error::{Error, QueueDenyError, QueueDenyExplanation, QueueEvaluation},
    pairing::Pairing,
    protocol::{Request, RequestBody, ResponseBody, WireMessage},
    transport,
    transport::Transport,
};
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
        Pairing::load_from_disk()
    }
}

impl Client {
    pub async fn send(
        &self,
        queue_uuid: Uuid,
        message: WireMessage,
        messaging_tokens: Option<&crate::protocol::MessagingTokens>,
        platform: Option<crate::protocol::PushDevicePlatform>,
    ) -> Result<(), Error> {
        let result = self
            .queue_client
            .send(queue_uuid, message.clone(), messaging_tokens, platform)
            .await;
        result?;
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

        self.send(
            queue_uuid,
            wire_message,
            pairing.messaging_tokens.as_ref(),
            pairing.platform,
        )
        .await?;

        let response = self
            .receive(queue_uuid, |messages| {
                pairing.find_response(&request.id, messages)
            })
            .await?;

        // Update messaging tokens and platform from response
        if let Some(messaging_tokens) = response.messaging_tokens {
            pairing.messaging_tokens = Some(messaging_tokens);
        }

        if let Some(platform) = response.platform {
            pairing.platform = Some(platform);
        }

        // Handle legacy device_token if messaging_tokens not present
        if pairing.messaging_tokens.is_none()
            && let Some(device_token) = response.device_token
        {
            pairing.device_token = Some(device_token);
            pairing.sanitize_device_token();
        }

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
