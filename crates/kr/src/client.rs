use crate::error::{QueueDenyError, QueueDenyExplanation, QueueEvaluation};
use crate::pairing::Pairing;
use crate::protocol::{Request, RequestBody, ResponseBody, WireMessage};
use crate::transport::krypton_aws::AwsClient;
use crate::transport::Transport;
use crate::{error::Error, transport};
use std::convert::TryFrom;
use transport::pzqueue::PZQueueClient;
use uuid::Uuid;

pub struct Client {
    pzq: PZQueueClient,
    aws: AwsClient,
}

impl Client {
    pub fn new() -> Result<Client, Error> {
        Ok(Client {
            pzq: PZQueueClient::new(),
            aws: AwsClient::new()?,
        })
    }

    pub fn pairing() -> Result<Pairing, Error> {
        Ok(Pairing::load_from_disk()?)
    }
}

impl Client {
    pub async fn create_queue(&self, uuid: Uuid) -> Result<(), Error> {
        let _ = self.aws.create_queue(uuid).await;
        Ok(())
    }

    pub async fn send(
        &self,
        device_token: Option<String>,
        queue_uuid: Uuid,
        message: WireMessage,
    ) -> Result<(), Error> {
        let pzq_send = self.pzq.send(device_token, queue_uuid, message.clone());
        let aws_send = self.aws.send(None, queue_uuid, message);

        // send both at the same time and wait for first success
        let (r1, r2) = futures::future::join(pzq_send, aws_send).await;
        if r1.is_err() && r2.is_err() {
            return r1;
        }

        Ok(())
    }

    pub async fn receive<T, F>(&self, queue_uuid: Uuid, on_messages: F) -> Result<T, Error>
    where
        F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send + Copy,
    {
        // receive the first one to complete
        let pzq_recv = self.pzq.receive(queue_uuid, on_messages);
        let aws_recv = self.aws.receive(queue_uuid, on_messages);

        let (res, _) = futures::future::select_ok(vec![pzq_recv, aws_recv]).await?;
        Ok(res)
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

        let response = match self
            .receive(queue_uuid, |messages| {
                pairing.find_response(&request.id, messages)
            })
            .await
        {
            Ok(res) => res,
            Err(error) => {
                if matches!(error, Error::NotPaired) {
                    Pairing::delete_pairing_file()?;
                }
                return Err(error);
            }
        };

        // special case to handle unpairing
        // TODO needed?
        if let ResponseBody::Unpair(_) = response.body {
            Pairing::delete_pairing_file()?;
            return Err(Error::NotPaired);
        }

        pairing.aws_push_id = response.aws_push_id.or(pairing.aws_push_id);
        pairing.device_token = response.device_token.or(pairing.device_token);
        pairing.store_to_disk()?;

        Ok(std::convert::TryFrom::try_from(response.body)?)
    }

    pub async fn pz_health_check(&self) -> Result<QueueEvaluation, Error> {
        match self.pzq.health_check().await {
            Ok(_) => Ok(QueueEvaluation::Allow),
            Err(error) => {
                eprintln!("PZQueue health check failed: {}", error);
                Ok(QueueEvaluation::Deny(QueueDenyError {
                    explanation: QueueDenyExplanation::PZQueueDown,
                }))
            }
        }
    }

    pub async fn aws_health_check(&self) -> Result<QueueEvaluation, Error> {
        match self.pzq.health_check().await {
            Ok(_) => Ok(QueueEvaluation::Allow),
            Err(error) => {
                eprintln!("AWS error: {}", error);
                Ok(QueueEvaluation::Deny(QueueDenyError {
                    explanation: QueueDenyExplanation::AWSQueueDown,
                }))
            }
        }
    }
}
