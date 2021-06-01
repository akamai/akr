#![allow(deprecated)]

mod cli;
use self::cli::*;

mod agent;

mod client;

mod error;
mod identity;
mod pairing;
mod protocol;
mod ssh_format;
mod transport;
mod util;

use clap::Clap;
use client::new_default_client;
use protocol::{RegisterRequest, RegisterResponse};
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

use crate::{client::Client, error::Error};
use crate::{
    pairing::{Keypair, Os, Pairing, PairingQr},
    ssh_format::SshFido2KeyPair,
};
use crate::{
    protocol::{
        Base64Buffer, IdRequest, IdResponse, Request, RequestBody, ResponseBody, PROTOCOL_VERSION,
    },
    util::set_user_protected_permissions,
};

use crate::identity::StoredIdentity;
use crate::transport::{krypton_aws::AwsClient, Transport};

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    sodiumoxide::init().map_err(|_| Error::CryptoInit).unwrap();

    let opts: Opts = Opts::parse();

    match opts.command {
        Command::Start => start_daemon().await,
        Command::Pair => pair().await?,
        Command::Generate { name, path } => generate(name, path).await?,
    }

    Ok(())
}

async fn pair() -> Result<(), Error> {
    let keypair: Keypair = sodiumoxide::crypto::box_::gen_keypair().into();
    let qr = PairingQr {
        public_key: keypair.public_key.clone(),
        version: PROTOCOL_VERSION.into(),
        name: whoami::devicename(),
        os: Os {
            version: whoami::platform().to_string(),
            kind: whoami::distro(),
            device_identifier: global_device_uuid()?,
        },
    };

    let client = new_default_client()?;
    let queue_uuid = keypair.queue_uuid()?;
    client.transport.create_queue(queue_uuid).await?;

    // print the qr code for pairing
    let raw = format!(
        "https://mfa.akamai.com/#{}",
        base64::encode(serde_json::to_string(&qr)?)
    );
    // qr2term::qr::Qr::from(raw)?.red
    qr2term::print_qr(raw).expect("failed to generate a qr code");

    let device_public_key = client
        .transport
        .receive(queue_uuid, |messages| {
            keypair.open_sealed_public_key(messages.first())
        })
        .await?;

    let mut pairing = Pairing {
        keypair,
        device_public_key: device_public_key.0.to_vec().into(),
        device_token: None,
        aws_push_id: None,
        device_name: String::new(),
    };

    let request = Request::new(RequestBody::Id(IdRequest {}));
    client
        .transport
        .send(None, queue_uuid, pairing.seal(&request)?)
        .await?;
    let response = client
        .transport
        .receive(queue_uuid, |messages| {
            pairing.find_response(&request.id, messages)
        })
        .await?;

    let id_response: IdResponse = match response.body {
        ResponseBody::Id(resp) => Into::<Result<IdResponse, Error>>::into(resp)?,
        _ => return Err(Error::InvalidPairingHelloMessage),
    };

    pairing.device_name = id_response.data.email;
    pairing.aws_push_id = response.aws_push_id;
    pairing.device_token = response.device_token;
    pairing.store_to_disk()?;

    let id = StoredIdentity {
        device_id: Some(id_response.data.device_identifier),
    };

    id.store_to_disk()?;

    eprintln!("\nPaired successfully!\n");
    // println!("{}", id.authorized_key_format()?);

    Ok(())
}

async fn generate(name: String, path: String) -> Result<(), Error> {
    let client = new_default_client()?;
    let name = format!("ssh:{}", name);
    let resp: RegisterResponse = client
        .send_request(RequestBody::Register(RegisterRequest {
            challenge: sodiumoxide::randombytes::randombytes(32).into(),
            rp_id: name.clone(),
            rp_name: None,
            user: None,
            is_webauthn: true,
        }))
        .await?;

    let key_pair = SshFido2KeyPair {
        application: name,
        key_handle: resp.key_handle.0,
        public_key: resp.public_key.0,
        flags: 0x01,
    };

    let public = format!("{}\n", key_pair.authorized_public_key()?);
    let pub_key_path = format!("{}.pub", &path);
    std::fs::write(&pub_key_path, public.as_bytes())?;
    set_user_protected_permissions(&pub_key_path)?;

    let private = key_pair.private_key_pem()?;
    let priv_key_path = format!("{}", &path);
    std::fs::write(&priv_key_path, private.as_bytes())?;
    set_user_protected_permissions(&priv_key_path)?;

    Ok(())
}

async fn start_daemon() {
    let home = create_home_path().expect("failed to create home dir");

    let pipe = format!("{}{}", home, SSH_AGENT_PIPE);
    let pipe = Path::new(pipe.as_str());

    if std::fs::metadata(&pipe).is_ok() {
        if let Ok(_) = std::fs::remove_file(&pipe) {
            println!("Pipe deleted");
        }
    }
    println!("binding to {}", pipe.display());
    let listener = UnixListener::bind(pipe);
    let handler = agent::Agent::new(Client {
        transport: AwsClient::new().expect("failed to create agent"),
    });
    ssh_agent::Agent::run(handler, listener.unwrap()).await;
}

pub const HOME_DIR: &'static str = "/.kr2/";
const SSH_AGENT_PIPE: &'static str = "krypton-ssh-agent.sock";

fn create_home_path() -> Result<String, Error> {
    let dirs = directories::UserDirs::new().ok_or(Error::CannotCreateHomeDir)?;
    let home = dirs.home_dir();

    let home = format!("{}{}", home.display(), HOME_DIR);
    let home_path = Path::new(home.as_str());
    if !Path::new(home_path).exists() {
        std::fs::create_dir(home_path)?;
    }
    Ok(home)
}

pub fn global_device_uuid() -> Result<Base64Buffer, Error> {
    let dirs = directories::UserDirs::new().ok_or(Error::PairingNotFound)?;
    let path = format!(
        "{}{}{}",
        dirs.home_dir().display(),
        crate::HOME_DIR,
        "global_device.uuid"
    );
    let path = Path::new(path.as_str());

    if !std::fs::metadata(&path).is_ok() {
        create_home_path()?;
        let uuid: Base64Buffer = sodiumoxide::randombytes::randombytes(32).into();
        std::fs::write(path, uuid.to_string())?;
        return Ok(uuid);
    }

    let uuid = base64::decode(&std::fs::read_to_string(path)?)?;
    Ok(uuid.into())
}
