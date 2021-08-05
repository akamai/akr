#![allow(deprecated)]

mod cli;
use self::cli::*;

mod ssh_agent;

mod client;

mod error;
mod identity;
mod launch;
mod pairing;
mod protocol;
mod setup;
mod ssh_format;
mod transport;
mod util;

use clap::Clap;
use protocol::UnpairRequest;
use protocol::{RegisterRequest, RegisterResponse};
use std::path::PathBuf;

use tokio::net::UnixListener;

use crate::client::Client;
use crate::error::Error;
use crate::protocol::{
    Base64Buffer, IdRequest, IdResponse, Request, RequestBody, ResponseBody, PROTOCOL_VERSION,
};
use crate::{
    pairing::{Keypair, Os, Pairing, PairingQr},
    ssh_format::SshFido2KeyPairHandle,
};

use crate::identity::StoredIdentity;
use ::ssh_agent::Agent as SshAgent;
use ansi_term::Colour::{Blue, Green, Red, Yellow};
use run_script::ScriptOptions;

pub const HOME_DIR: &'static str = ".akr";
const SSH_AGENT_PIPE: &'static str = "akr-ssh-agent.sock";

#[tokio::main]
async fn main() {
    env_logger::init();
    sodiumoxide::init().map_err(|_| Error::CryptoInit).unwrap();

    let result = handle_command().await;
    if let Err(e) = result {
        eprintln!("Error: {}", Red.paint(e.to_string()));
    }
}

async fn handle_command() -> Result<(), Error> {
    let opts: Opts = Opts::parse();

    match opts.command {
        Command::Start => start_daemon().await,
        Command::Pair { setup } => {
            if setup {
                setup::run(SetupArgs {
                    print_only: false,
                    ssh_config_path: None,
                })
                .await?
            }
            pair().await?
        }
        Command::Unpair => unpair().await?,
        Command::Status => get_pairing_details().await?,
        Command::Generate { name } => generate(name).await?,
        Command::Load => load_keys().await?,
        Command::Setup(args) => setup::run(args).await?,
        Command::Check => health_check().await?,
    }

    Ok(())
}

async fn pair() -> Result<(), Error> {
    let mut client = Client::new()?;
    let mut already_paired = false;
    let mut paired_device_name = "".to_string();

    //IdResponse
    let id_response_result: Result<IdResponse, Error> = client
        .send_request(RequestBody::Id(IdRequest {
            send_sk_accounts: true,
        }))
        .await;

    match id_response_result {
        Ok(id_response) => {
            already_paired = true;
            paired_device_name = id_response.data.device_name;
        }
        Err(_) => {}
    }

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

    let queue_uuid = keypair.queue_uuid()?;
    client.create_queue(queue_uuid).await?;

    // print the qr code for pairing
    let raw = format!(
        "https://mfa.akamai.com/#{}",
        base64::encode(serde_json::to_string(&qr)?)
    );
    qr2term::print_qr(raw).expect("failed to generate a qr code");
    if already_paired {
        eprintln!("You are already paired with device {}. \nTo override, scan the above QR code to pair a new device ", Yellow.paint(paired_device_name));
    } else {
        eprintln!(
            "{}",
            Green.paint("Scan the above QR code to pair your device...")
        );
    }

    let device_public_key = client
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

    let request = Request::new(RequestBody::Id(IdRequest {
        send_sk_accounts: true,
    }));
    client
        .send(None, queue_uuid, pairing.seal(&request)?)
        .await?;
    let response = client
        .receive(queue_uuid, |messages| {
            pairing.find_response(&request.id, messages)
        })
        .await?;

    let id_response: IdResponse = match response.body {
        ResponseBody::Id(resp) => Into::<Result<IdResponse, Error>>::into(resp)?,
        _ => return Err(Error::InvalidPairingHelloMessage),
    };

    pairing.device_name = id_response.data.device_name.clone();
    pairing.aws_push_id = response.aws_push_id;
    pairing.device_token = response.device_token;
    pairing.store_to_disk()?;

    let id = StoredIdentity {
        device_id: Some(id_response.data.device_identifier),
        key_pair_handles: id_response
            .data
            .sk_accounts
            .unwrap_or(vec![])
            .into_iter()
            .map(|sk| SshFido2KeyPairHandle {
                application: sk.rp_id,
                key_handle: sk.key_handle.0,
                flags: 0x01,
                public_key: sk.public_key.0,
            })
            .collect(),
    };

    id.store_to_disk()?;
    eprintln!(
        "\n{} {}.\n",
        Green.paint("Paired successfully with"),
        Green.paint(id_response.data.device_name)
    );
    Ok(())
}

async fn unpair() -> Result<(), Error> {
    let mut client = Client::new()?;
    let pairing = Client::pairing()?;
    let queue_uuid = pairing.queue_uuid()?;
    let request = Request::new(RequestBody::Unpair(UnpairRequest {}));
    let wire_message = pairing.seal(&request)?;

    let _ = client
        .send(pairing.device_token.clone(), queue_uuid, wire_message)
        .await?;

    Pairing::delete_pairing_file()?;
    eprintln!("\n{}\n", Green.paint("Unpaired successfully!"));
    Ok(())
}

async fn get_pairing_details() -> Result<(), Error> {
    let mut client = Client::new()?;

    let id_response: IdResponse = client
        .send_request(RequestBody::Id(IdRequest {
            send_sk_accounts: true,
        }))
        .await?;

    eprintln!(
        "Paired with {}",
        Green.bold().paint(id_response.data.device_name)
    );
    Ok(())
}

async fn generate(name: String) -> Result<(), Error> {
    let mut client = Client::new()?;
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

    let key_pair = SshFido2KeyPairHandle {
        application: name,
        key_handle: resp.key_handle.0,
        public_key: resp.public_key.0,
        flags: 0x01,
    };

    StoredIdentity::store_key_pair_handle(&key_pair)?;

    eprintln!("{}", key_pair.authorized_public_key()?);

    Ok(())
}

async fn load_keys() -> Result<(), Error> {
    let mut client = Client::new()?;

    let id_response: IdResponse = client
        .send_request(RequestBody::Id(IdRequest {
            send_sk_accounts: true,
        }))
        .await?;

    let id = StoredIdentity {
        device_id: Some(id_response.data.device_identifier),
        key_pair_handles: id_response
            .data
            .sk_accounts
            .unwrap_or(vec![])
            .into_iter()
            .map(|sk| SshFido2KeyPairHandle {
                application: sk.rp_id,
                key_handle: sk.key_handle.0,
                flags: 0x01,
                public_key: sk.public_key.0,
            })
            .collect(),
    };

    id.store_to_disk()?;

    for k in id.key_pair_handles {
        if !k.application.starts_with("ssh:") {
            continue;
        }
        eprintln!("{}", Blue.paint(k.authorized_public_key()?));
    }

    Ok(())
}

async fn start_daemon() {
    let home = create_home_path().expect("failed to create home dir");
    let pipe = home.join(SSH_AGENT_PIPE);

    if std::fs::metadata(&pipe).is_ok() {
        if let Ok(_) = std::fs::remove_file(&pipe) {
            eprintln!("Pipe deleted");
        }
    }
    eprintln!("binding to {}", pipe.display());
    let listener = UnixListener::bind(pipe);
    let handler = ssh_agent::Agent::new(Client::new().expect("failed to startup client"));
    SshAgent::run(handler, listener.unwrap()).await;
}

async fn health_check() -> Result<(), Error> {
    let mut client = Client::new()?;
    let mut errors_encountered = false;

    // check if queues are working properly or not
    match client.pz_health_check().await? {
        error::QueueEvaluation::Allow => {}
        error::QueueEvaluation::Deny(reason) => {
            eprintln!("{}", Red.paint(reason.to_string()));
            errors_encountered = true;
        }
    }
    match client.aws_health_check().await? {
        error::QueueEvaluation::Allow => {}
        error::QueueEvaluation::Deny(reason) => {
            eprintln!("{}", Red.paint(reason.to_string()));
            errors_encountered = true;
        }
    }

    // check if ssh 8.2+ is installed or not
    let (ssh_code, ssh_output, ssh_error) = run_script::run(
        r#"
        [[ $(ssh -V 2>&1) =~ [0-9.]+ ]];echo $BASH_REMATCH
         "#,
        &vec![],
        &ScriptOptions::new(),
    )
    .map_err(|error| Error::RunScriptError(error))?;

    // TODO print ssh version
    if ssh_error == "" && ssh_code == 0 {
        match ssh_output.trim().parse::<f64>() {
            Ok(version) => {
                if version < 8.2 {
                    eprintln!("{}", Red.paint("OpenSSH 8.2+ is required to use akr"));
                    errors_encountered = true;
                }
            }
            Err(error) => {
                eprintln!("{} {}",Red.paint("Couldn't parse ssh version. Please manually check to make sure you have Openssh 8.2+ installed."), error);
            }
        }
    }

    //check if the user has any keys
    let id_response: IdResponse = client
        .send_request(RequestBody::Id(IdRequest {
            send_sk_accounts: true,
        }))
        .await?;

    let id_filtered: Vec<SshFido2KeyPairHandle> = id_response
        .data
        .sk_accounts
        .unwrap_or(vec![])
        .into_iter()
        .map(|sk| SshFido2KeyPairHandle {
            application: sk.rp_id,
            key_handle: sk.key_handle.0,
            flags: 0x01,
            public_key: sk.public_key.0,
        })
        .collect::<Vec<SshFido2KeyPairHandle>>()
        .into_iter()
        .filter(|x| x.application.starts_with("ssh:"))
        .collect();

    if id_filtered.is_empty() {
        eprintln!("{}",Red.paint("You do not have any keys loaded in your agent. Please generate one using `akr generate --name <key_name>`"));
        errors_encountered = true;
    }

    if !errors_encountered {
        eprintln!("{}", Green.paint("You're all set! "));
    }

    Ok(())
}

fn create_home_path() -> Result<PathBuf, Error> {
    let dirs = directories::UserDirs::new().ok_or(Error::CannotCreateHomeDir)?;
    let home = dirs.home_dir().join(HOME_DIR);
    if !home.exists() {
        std::fs::create_dir(&home)?;
    }
    Ok(home)
}

pub fn global_device_uuid() -> Result<Base64Buffer, Error> {
    let path = create_home_path()?.join("global_device.uuid");

    if !std::fs::metadata(&path).is_ok() {
        let uuid: Base64Buffer = sodiumoxide::randombytes::randombytes(32).into();
        std::fs::write(path, uuid.to_string())?;
        return Ok(uuid);
    }

    let uuid = base64::decode(&std::fs::read_to_string(path)?)?;
    Ok(uuid.into())
}
