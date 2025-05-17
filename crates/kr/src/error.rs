use openssl::error::ErrorStack;
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

    #[error("Sign flags contain incompatible bits")]
    IllegalFlags,

    #[error("Openssl operation failed: {0}")]
    SslError(#[from] ErrorStack),

    #[error("Invalid Bytes")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("Unable to parse key")]
    OsshKeysError(#[from] osshkeys::error::Error),
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
    QueueDown,
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
            QueueDown => "Akamai MFA not reachable. Please make sure you can reach mfa.akamai.com",
        };
        f.write_str(&format!("{}", explanation))
    }
}

#[derive(Debug)]
pub enum QueueEvaluation {
    Allow,
    Deny(QueueDenyError),
}
