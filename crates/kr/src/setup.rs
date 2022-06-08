use std::path::Path;

use super::SetupArgs;
use crate::{error::Error, launch::Daemon};

pub async fn run(args: SetupArgs) -> Result<(), Error> {
    if args.print_only {
        return print_config();
    }

    update_ssh_config(args.ssh_config_path).await?;
    Daemon::new()?.install()
}

/// print out config changes
pub fn print_config() -> Result<(), Error> {
    println!(
        "== SSH Config Additions ==\n{}\n",
        create_ssh_config_stanza()?
    ); //TODO:ssh config
    println!("==  Background Service  ==\n{}\n", Daemon::new()?.render()?);
    Ok(())
}

const BEGIN_CONFIG_STANZA: &'static str = "# Begin Akamai MFA SSH Config";
const END_CONFIG_STANZA: &'static str = "# End Akamai MFA SSH Config";

const BEGIN_KR_STANZA: &'static str = "# Added by Krypton";
const KR_PROXY_COMMAND_STANZA: &'static str = "krssh %h %p";

fn create_ssh_config_stanza() -> Result<String, Error> {
    let agent_socket_path = crate::create_home_path()?
        .join(crate::SSH_AGENT_PIPE)
        .display()
        .to_string();

    // create the new config
    let mut stanza = String::new();
    stanza.push_str("\n");
    stanza.push_str(BEGIN_CONFIG_STANZA);
    stanza.push_str("\n");
    stanza.push_str("Host *\n");
    stanza.push_str("\tIdentityAgent ");
    stanza.push_str(&agent_socket_path);
    stanza.push_str("\n");
    stanza.push_str(END_CONFIG_STANZA);
    stanza.push_str("\n");

    Ok(stanza)
}

/// add our host stanza to the config file
pub async fn update_ssh_config(custom_path: Option<String>) -> Result<(), Error> {
    let path = if let Some(custom) = custom_path {
        Path::new(&custom).into()
    } else {
        directories::UserDirs::new()
            .ok_or(Error::CannotReadHomeDir)?
            .home_dir()
            .join(".ssh")
            .join("config")
    };

    let ssh_config = std::fs::read_to_string(&path)?;

    // clear any existing config by us
    let mut lines: Vec<&str> = ssh_config.split("\n").collect();
 
    let start = lines
        .iter_mut()
        .position(|s| s.as_bytes() == BEGIN_CONFIG_STANZA.as_bytes());
    let end = lines
        .iter_mut()
        .position(|s| s.as_bytes() == END_CONFIG_STANZA.as_bytes());

        let clean_akr_config_lines = match (start, end) {
        (Some(start), Some(end)) => vec![&lines[..start], &lines[(end + 1)..]]
            .concat()
            .join("\n"),
        _ => lines.join("\n"),
    };

    // clean up old kr stanza if any 
    let mut lines_updated: Vec<&str> = clean_akr_config_lines.split("\n").collect();
    let kr_start = lines_updated
        .iter_mut()
        .position(|s| s.as_bytes() == BEGIN_KR_STANZA.as_bytes());
    let kr_end = lines_updated
        .iter_mut()
        .position(|s| s.contains(KR_PROXY_COMMAND_STANZA));

    let mut clean_config = match (kr_start, kr_end) {
        (Some(kr_start), Some(kr_end)) => vec![&lines_updated[..kr_start], &lines_updated[(kr_end + 1)..]]
            .concat()
            .join("\n"),
        _ => lines_updated.join("\n"),
    };

    clean_config.push_str(&create_ssh_config_stanza()?);
    Ok(std::fs::write(&path, clean_config)?)
}
