use run_script::ScriptError;
use std::convert::Infallible;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON serialization error: '{0}'")]
    Json(#[from] serde_json::Error),

    #[error("File IO error: '{0}'")]
    IOError(#[from] std::io::Error),

    #[error("Invalid pairing key")]
    InvalidPairingKeys,

    #[error("Cannot create home directory")]
    CannotCreateHomeDir,

    #[error("Cannot read home directory")]
    CannotReadHomeDir,

    #[error("Invalid pairing hello")]
    InvalidPairingHelloMessage,

    #[error("Invalid crypto initialization")]
    CryptoInit,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Failed to open ciphertext")]
    UnsealFailed,

    #[error("Invalid wire message")]
    InvalidWireProtocol,

    #[error("Invalid response message received")]
    UnexpectedResponse,

    #[error("Not paired with Akamai MFA. Please run the `pair` command.")]
    NotPaired,

    #[error("Failed to load stored id")]
    StoredIdentityNotFound,

    #[error("Invalid authenticator data received")]
    BadAuthenticatorData,

    #[error("QR Code rendering failed: '{0}'")]
    QrCodeRendering(#[from] qr2term::QrError),

    #[error("Invalid utf8 contents: '{0}'")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("AWS Http TLS error: '{0}'")]
    AwsHttpClient(#[from] rusoto_core::request::TlsError),

    #[error("AWS SQS Send error: '{0}'")]
    AwsSqsSendError(#[from] rusoto_core::RusotoError<rusoto_sqs::SendMessageError>),

    #[error("AWS SQS Create Queue error: '{0}'")]
    AwsSqsCreateQueueError(#[from] rusoto_core::RusotoError<rusoto_sqs::CreateQueueError>),

    #[error("AWS SQS Receive error: '{0}'")]
    AwsSqsReceiveError(#[from] rusoto_core::RusotoError<rusoto_sqs::ReceiveMessageError>),

    #[error("AWS SQS Delete error: '{0}'")]
    AwsSqsDeleteError(#[from] rusoto_core::RusotoError<rusoto_sqs::DeleteMessageBatchError>),

    #[error("AWS SNS Publish error: '{0}'")]
    AwsSnsPublishError(#[from] rusoto_core::RusotoError<rusoto_sns::PublishError>),

    #[error("UUID invalid: '{0}'")]
    InvalidUUID(#[from] uuid::Error),

    #[error("Base64 invalid: '{0}'")]
    Base64Encoding(#[from] base64::DecodeError),

    #[error("Response was never received")]
    ResponseTimedOut,

    #[error("Unknown key selected")]
    UnknownKey,

    #[error("Invalid RP prefix")]
    BadRpPrefix,

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Request error: {0}")]
    HttpRequestError(#[from] reqwest::Error),

    #[error("Template error: {0}")]
    TemplateFailed(#[from] askama::Error),

    #[error("Couldn't Parse SSH version: '{0}'")]
    RunScriptError(#[from] ScriptError),
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<Error> for ssh_agent::error::Error {
    fn from(error: Error) -> ssh_agent::error::Error {
        ssh_agent::error::Error {
            details: format!("Error: {:?}", error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QueueDenyExplanation {
    PZQueueDown,
    AWSQueueDown,
}

/// A richer error type for errors returned from the evaluation of user agents.
#[derive(Debug)]
pub struct QueueDenyError {
    pub explanation: QueueDenyExplanation,
}
impl std::fmt::Display for QueueDenyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use QueueDenyExplanation::*;
        let explanation = match self.explanation {
            PZQueueDown => "Akamai MFA not reachable. Please make sure you can reach mfa.akamai.com",
            AWSQueueDown => "AWS is down or unreachable. Please make sure you can reach sqs.us-east-1.amazonaws.com ",
        };
        f.write_str(&format!("{}", explanation))
    }
}

#[derive(Debug)]
pub enum QueueEvaluation {
    Allow,
    Deny(QueueDenyError),
}
