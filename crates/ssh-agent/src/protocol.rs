use std::io::{self, Write};

use tokio::net::UnixStream;

use crate::error::{ParsingError, WritingError};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Copy, Clone)]
enum MessageRequest {
    RequestIdentities,
    SignRequest,
    AddIdentity,
    RemoveIdentity,
    RemoveAllIdentities,
    AddIdConstrained,
    AddSmartcardKey,
    RemoveSmartcardKey,
    Lock,
    Unlock,
    AddSmartcardKeyConstrained,
    Extension,
    Unknown,
}

impl MessageRequest {
    fn from_u8(value: u8) -> MessageRequest {
        match value {
            11 => MessageRequest::RequestIdentities,
            13 => MessageRequest::SignRequest,
            17 => MessageRequest::AddIdentity,
            18 => MessageRequest::RemoveIdentity,
            19 => MessageRequest::RemoveAllIdentities,
            25 => MessageRequest::AddIdConstrained,
            20 => MessageRequest::AddSmartcardKey,
            21 => MessageRequest::RemoveSmartcardKey,
            22 => MessageRequest::Lock,
            23 => MessageRequest::Unlock,
            26 => MessageRequest::AddSmartcardKeyConstrained,
            27 => MessageRequest::Extension,
            _ => MessageRequest::Unknown,
        }
    }
}

async fn read_message<R: AsyncRead + Unpin>(stream: &mut R) -> ParsingError<Vec<u8>> {
    let len = stream.read_u32().await?;

    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf).await?;

    Ok(buf)
}

async fn read_string<R: AsyncRead + Unpin>(stream: &mut R) -> ParsingError<String> {
    let len = stream.read_u32().await?;

    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf).await?;

    if buf.is_empty() {
        return Ok(String::new());
    }
    let res = std::str::from_utf8(&buf).map_err(|_| crate::error::Error {
        details: "invalid type found, expected string".into(),
    })?;

    Ok(res.to_string())
}

async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, string: &[u8]) -> WritingError<()> {
    w.write_u32(string.len() as u32).await?;
    w.write_all(string).await?;
    Ok(())
}

/// This is used to format a SSH signature.
fn write_string<W: Write>(w: &mut W, string: &[u8]) -> io::Result<()> {
    w.write_u32::<BigEndian>(string.len() as u32)?;
    w.write_all(string)
}

#[derive(Debug)]
pub enum Request {
    RequestIdentities,
    AddIdentity {
        key_type: String,
        key_contents: Vec<u8>,
    },
    SignRequest {
        // Blob of the public key
        // (encoded as per RFC4253 "6.6. Public Key Algorithms").
        pubkey_blob: Vec<u8>,
        // The data to sign.
        data: Vec<u8>,
        // Request flags.
        flags: u32,
    },
    Unknown,
}
impl Request {
    pub async fn read(stream: &mut UnixStream) -> ParsingError<Self> {
        debug!("reading request");
        let raw_msg = read_message(stream).await?;
        let mut buf = raw_msg.as_slice();

        let msg = ReadBytesExt::read_u8(&mut buf)?;
        match MessageRequest::from_u8(msg) {
            MessageRequest::RequestIdentities => Ok(Request::RequestIdentities),
            MessageRequest::SignRequest => Ok(Request::SignRequest {
                pubkey_blob: read_message(&mut buf).await?,
                data: read_message(&mut buf).await?,
                flags: ReadBytesExt::read_u32::<BigEndian>(&mut buf)?,
            }),
            MessageRequest::AddIdentity | MessageRequest::AddIdConstrained => {
                let key_type = read_string(&mut buf).await?;
                let key_contents = buf.to_vec();

                Ok(Request::AddIdentity {
                    key_type,
                    key_contents,
                })
            }
            MessageRequest::RemoveIdentity => Ok(Request::Unknown),
            MessageRequest::RemoveAllIdentities => Ok(Request::Unknown),
            MessageRequest::AddSmartcardKey => Ok(Request::Unknown),
            MessageRequest::RemoveSmartcardKey => Ok(Request::Unknown),
            MessageRequest::Lock => Ok(Request::Unknown),
            MessageRequest::Unlock => Ok(Request::Unknown),
            MessageRequest::AddSmartcardKeyConstrained => Ok(Request::Unknown),
            MessageRequest::Extension => Ok(Request::Unknown),
            MessageRequest::Unknown => {
                debug!("Unknown request {}", msg);
                Ok(Request::Unknown)
            }
        }
    }
}

enum MessageResponse {
    AgentFailure = 5,
    AgentSuccess = 6,
    AgentIdentitiesAnswer = 12,
    AgentSignResponse = 14,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub key_comment: String,
}

#[derive(Debug)]
pub enum Response {
    Success,
    Failure,
    Identities(Vec<Identity>),
    SignResponse {
        signature: Vec<u8>,
    },
    SignResponse2 {
        /// Name of the signature algorithm used. This is prepended as a `string`.
        algo_name: String,
        /// Actual signature blob.
        signature: Vec<u8>,
    },
}

impl Response {
    pub async fn write(&self, stream: &mut UnixStream) -> WritingError<()> {
        let mut buf = Vec::new();
        match *self {
            Response::Success => {
                WriteBytesExt::write_u8(&mut buf, MessageResponse::AgentSuccess as u8)?
            }
            Response::Failure => {
                WriteBytesExt::write_u8(&mut buf, MessageResponse::AgentFailure as u8)?
            }
            Response::Identities(ref identities) => {
                WriteBytesExt::write_u8(&mut buf, MessageResponse::AgentIdentitiesAnswer as u8)?;
                WriteBytesExt::write_u32::<BigEndian>(&mut buf, identities.len() as u32)?;

                for identity in identities {
                    write_message(&mut buf, &identity.key_blob).await?;
                    write_message(&mut buf, &identity.key_comment.as_bytes()).await?;
                }
            }
            Response::SignResponse { ref signature } => {
                WriteBytesExt::write_u8(&mut buf, MessageResponse::AgentSignResponse as u8)?;
                write_message(&mut buf, signature.as_slice()).await?;
            }

            Response::SignResponse2 {
                ref algo_name,
                ref signature,
            } => {
                WriteBytesExt::write_u8(&mut buf, MessageResponse::AgentSignResponse as u8)?;

                let mut full_sig = Vec::new();
                write_string(&mut full_sig, algo_name.as_bytes())?;
                write_string(&mut full_sig, signature)?;

                write_string(&mut buf, &full_sig)?;
            }
        }
        stream.write_u32(buf.len() as u32).await?;
        stream.write_all(&buf).await?;
        Ok(())
    }
}
