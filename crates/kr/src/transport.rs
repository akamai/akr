use crate::error::Error;
use crate::protocol::Base64Buffer;
use crate::protocol::WireMessage;
use async_trait::async_trait;
use serde::Serialize;
use uuid::Uuid;
#[async_trait]
pub trait Transport {
    async fn create_queue(&self, queue_uuid: Uuid) -> Result<(), Error>;
    async fn send(
        &self,
        device_token: Option<String>,
        queue_uuid: Uuid,
        message: WireMessage,
    ) -> Result<(), Error>;
    async fn receive<T, F>(&self, queue_uuid: Uuid, on_messages: F) -> Result<T, Error>
    where
        F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send;

    async fn health_check(&self) -> Result<(), Error>;
}

pub mod pzqueue {
    use super::*;
    use uuid::Uuid;
    #[derive(Clone)]
    pub struct PZQueueClient {
        client: reqwest::Client,
    }
    pub struct QueueName(Uuid);
    impl QueueName {
        pub fn send(&self) -> String {
            self.0.to_string().to_uppercase().replace("-", "")
        }

        pub fn receive(&self) -> String {
            format!("{}_responder", self.send())
        }
    }

    impl PZQueueClient {
        const URL: &'static str = "https://mfa.akamai.com/api/v1/device/krypton/channel";

        pub fn new() -> Self {
            Self {
                client: reqwest::Client::new(),
            }
        }

        async fn send_inner(
            &self,
            queue_name: &str,
            device_token: Option<String>,
            message: WireMessage,
        ) -> Result<(), Error> {
            let query = device_token
                .map(|t| format!("?device_token={}", t))
                .unwrap_or("".to_string());
            let url = format!("{}/{}{}", Self::URL, queue_name, query);

            let message = Base64Buffer(message.into_wire()).to_string();
            let _ = self.client.post(url).body(message).send().await?;
            Ok(())
        }

        async fn receive_inner<T, F>(&self, queue_name: &str, on_messages: F) -> Result<T, Error>
        where
            F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send,
        {
            let url = format!("{}/{}?poll_wait_secs=10", Self::URL, queue_name);

            // only try for 60s
            let timeout = 60i64;
            let mut duration = 0i64;
            while duration < timeout {
                let now = chrono::Utc::now().timestamp();
                let res: Res<Messages> = self.client.get(&url).send().await?.json().await?;
                let wire: Vec<WireMessage> = res
                    .result
                    .messages
                    .into_iter()
                    .filter_map(|m| WireMessage::new(m.0).ok())
                    .collect();

                duration += chrono::Utc::now().timestamp() - now;

                if let Some(res) = on_messages(&wire)? {
                    return Ok(res);
                }
            }

            Err(Error::ResponseTimedOut)
        }
    }

    #[derive(Debug, serde::Deserialize)]
    struct Res<T> {
        result: T,
    }

    #[derive(Debug, serde::Deserialize)]
    struct Messages {
        messages: Vec<Base64Buffer>,
    }

    #[async_trait]
    impl Transport for PZQueueClient {
        async fn create_queue(&self, _: Uuid) -> Result<(), Error> {
            Ok(())
        }

        async fn send(
            &self,
            device_token: Option<String>,
            queue_uuid: Uuid,
            message: WireMessage,
        ) -> Result<(), Error> {
            let queue = QueueName(queue_uuid);
            self.send_inner(&queue.send(), device_token, message).await
        }

        async fn receive<T, F>(&self, queue_uuid: Uuid, on_messages: F) -> Result<T, Error>
        where
            F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send,
        {
            let queue = QueueName(queue_uuid);
            self.receive_inner(&queue.receive(), on_messages).await
        }

        async fn health_check(&self) -> Result<(), Error> {
            let queue_uuid = Uuid::new_v4();
            self.create_queue(queue_uuid).await?;
            let fake_message: Vec<u8> = sodiumoxide::randombytes::randombytes(4);
            let msg = WireMessage::SealedMessage(fake_message.clone());

            let queue = QueueName(queue_uuid);
            self.send_inner(&queue.receive(), None, msg).await?;

            self.receive(queue_uuid, |msg| {
                for wire_message in msg {
                    if wire_message.clone().data().eq(&fake_message) {
                        return Ok(Some(fake_message.clone()));
                    }
                }
                Err(Error::UnexpectedResponse)
            })
            .await?;

            Ok(())
        }
    }
}

pub mod krypton_aws {
    use super::*;
    use rusoto_core::credential::StaticProvider;
    use rusoto_core::{HttpClient, Region};
    use rusoto_sns::{PublishInput, Sns, SnsClient};
    use rusoto_sqs::{
        CreateQueueRequest, DeleteMessageBatchRequest, DeleteMessageBatchRequestEntry,
        ReceiveMessageRequest, SendMessageRequest, Sqs, SqsClient,
    };

    #[derive(Clone)]
    pub struct AwsClient {
        sqs: SqsClient,
        sns: SnsClient,
    }

    pub type SnsEndpointArn = String;

    #[async_trait]
    impl Transport for AwsClient {
        async fn create_queue(&self, queue_uuid: Uuid) -> Result<(), Error> {
            let queue = QueueName(queue_uuid);
            self.create_queue_inner(&queue).await
        }

        async fn send(
            &self,
            device_token: Option<SnsEndpointArn>,
            queue_uuid: Uuid,
            message: WireMessage,
        ) -> Result<(), Error> {
            self.create_queue(queue_uuid).await?;
            let queue = QueueName(queue_uuid);
            self.send_inner(&queue.send(), device_token, message).await
        }

        async fn receive<T, F>(&self, queue_uuid: Uuid, on_messages: F) -> Result<T, Error>
        where
            F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send,
        {
            self.create_queue(queue_uuid).await?;
            let queue = QueueName(queue_uuid);
            self.receive_inner(&queue.receive(), on_messages).await
        }

        async fn health_check(&self) -> Result<(), Error> {
            let fake_message: Vec<u8> = sodiumoxide::randombytes::randombytes(4);

            let queue_uuid = Uuid::new_v4();
            self.create_queue(queue_uuid).await?;
            let queue = QueueName(queue_uuid);

            let msg = WireMessage::SealedMessage(fake_message.clone());
            self.send_inner(&queue.receive(), None, msg).await?;

            self.receive(queue_uuid, |msg| {
                for wire_message in msg {
                    if wire_message.clone().data().eq(&fake_message) {
                        return Ok(Some(fake_message.clone()));
                    }
                }
                Err(Error::UnexpectedResponse)
            })
            .await?;

            Ok(())
        }
    }

    pub struct QueueName(Uuid);
    impl QueueName {
        pub fn send(&self) -> String {
            self.0.to_string().to_uppercase()
        }

        pub fn receive(&self) -> String {
            format!("{}-responder", self.send())
        }
    }

    impl AwsClient {
        const ACCESS_KEY: &'static str = "AKIAJMZJ3X6MHMXRF7QQ";
        const SECRET_KEY: &'static str = "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";
        const QUEUE_URL_BASE: &'static str = "https://sqs.us-east-1.amazonaws.com/911777333295";

        pub fn new() -> Result<Self, Error> {
            let provider =
                StaticProvider::new(Self::ACCESS_KEY.into(), Self::SECRET_KEY.into(), None, None);
            let sqs = SqsClient::new_with(HttpClient::new()?, provider.clone(), Region::UsEast1);
            let sns = SnsClient::new_with(HttpClient::new()?, provider.clone(), Region::UsEast1);
            Ok(Self { sqs, sns })
        }

        async fn create_queue_inner(&self, queue_name: &QueueName) -> Result<(), Error> {
            let _ = self
                .sqs
                .create_queue(CreateQueueRequest {
                    queue_name: queue_name.send(),
                    ..Default::default()
                })
                .await?;

            let _ = self
                .sqs
                .create_queue(CreateQueueRequest {
                    queue_name: queue_name.receive(),
                    ..Default::default()
                })
                .await?;

            Ok(())
        }

        async fn send_inner(
            &self,
            queue_name: &str,
            sns_endpoint_arn: Option<String>,
            message: WireMessage,
        ) -> Result<(), Error> {
            let message = base64::encode(message.into_wire());
            let _ = self
                .sqs
                .send_message(SendMessageRequest {
                    message_body: message.clone(),
                    queue_url: format!("{}/{}", Self::QUEUE_URL_BASE, queue_name),
                    ..Default::default()
                })
                .await?;

            if let Some(arn) = sns_endpoint_arn {
                let apns = serde_json::to_string(&ApnsPayload {
                    aps: ApsData {
                        alert: "Krypton Request",
                        ciphertext: &message,
                        content_available: 1,
                        mutable_content: 1,
                        queue: queue_name,
                        session_uuid: queue_name,
                    },
                })?;

                let gcm = serde_json::to_string(&GcmPayload {
                    data: GcmData {
                        message: &message,
                        queue: queue_name,
                    },
                    delay_while_idle: false,
                    priority: "high",
                    time_to_live: 0,
                })?;

                let sns_message = SnsMessage {
                    apns: &apns,
                    apns_sandbox: &apns,
                    gcm: &gcm,
                };

                let _ = self
                    .sns
                    .publish(PublishInput {
                        message: serde_json::to_string(&sns_message)?,
                        message_structure: Some("json".to_string()),
                        target_arn: Some(arn),
                        ..Default::default()
                    })
                    .await?;
            }

            Ok(())
        }

        async fn receive_inner<T, F>(&self, queue_name: &str, on_messages: F) -> Result<T, Error>
        where
            F: Fn(&[WireMessage]) -> Result<Option<T>, Error> + Send,
        {
            // only try for 60s
            let timeout = 60i64;
            let mut duration = 0i64;
            while duration < timeout {
                let now = chrono::Utc::now().timestamp();
                let result = self
                    .sqs
                    .receive_message(ReceiveMessageRequest {
                        queue_url: format!("{}/{}", Self::QUEUE_URL_BASE, queue_name),
                        wait_time_seconds: Some(20),
                        max_number_of_messages: Some(10),
                        ..Default::default()
                    })
                    .await?;
                duration += chrono::Utc::now().timestamp() - now;

                let messages = result.messages.unwrap_or(vec![]);
                let receipts = messages
                    .iter()
                    .filter_map(|m| match (&m.message_id, &m.receipt_handle) {
                        (Some(id), Some(rh)) => Some((id.clone(), rh.clone())),
                        _ => None,
                    })
                    .collect();

                let wire_messages: Vec<WireMessage> = messages
                    .into_iter()
                    .filter_map(|m| m.body)
                    .filter_map(|m| base64::decode(&m).ok())
                    .filter_map(|m| WireMessage::new(m).ok())
                    .collect();

                let _ = self.delete_batch(queue_name, receipts).await;

                if let Some(resp) = on_messages(&wire_messages)? {
                    return Ok(resp);
                }
            }

            return Err(Error::ResponseTimedOut);
        }

        async fn delete_batch(
            &self,
            queue_name: &str,
            receipts: Vec<(String, String)>,
        ) -> Result<(), Error> {
            let _ = self
                .sqs
                .delete_message_batch(DeleteMessageBatchRequest {
                    queue_url: format!("{}/{}", Self::QUEUE_URL_BASE, queue_name),
                    entries: receipts
                        .into_iter()
                        .map(|r| DeleteMessageBatchRequestEntry {
                            id: r.0,
                            receipt_handle: r.1,
                        })
                        .collect(),
                })
                .await?;

            Ok(())
        }
    }

    #[derive(Debug, Clone, Serialize)]
    struct ApnsPayload<'a> {
        aps: ApsData<'a>,
    }

    #[derive(Debug, Clone, Serialize)]
    struct ApsData<'a> {
        alert: &'a str,
        queue: &'a str,
        session_uuid: &'a str,

        #[serde(rename = "c")]
        ciphertext: &'a str,

        #[serde(rename = "content-available")]
        content_available: u8,
        #[serde(rename = "mutable-content")]
        mutable_content: u8,
    }

    #[derive(Debug, Clone, Serialize)]
    struct GcmPayload<'a> {
        data: GcmData<'a>,
        delay_while_idle: bool,
        priority: &'a str,
        time_to_live: u64,
    }

    #[derive(Debug, Clone, Serialize)]
    struct GcmData<'a> {
        message: &'a str,
        queue: &'a str,
    }

    #[derive(Debug, Clone, Serialize)]
    struct SnsMessage<'a> {
        #[serde(rename = "APNS")]
        apns: &'a str,
        #[serde(rename = "APNS_SANDBOX")]
        apns_sandbox: &'a str,
        #[serde(rename = "GCM")]
        gcm: &'a str,
    }
}
