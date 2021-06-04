use std::path::Path;

use super::SetupArgs;
use crate::{error::Error, launch::Daemon};

pub async fn run(args: SetupArgs) -> Result<(), Error> {
    if args.print_only {
        return print_config();
    }

    update_ssh_config(args.ssh_config_path).await?;
    Daemon::new().install()
}

/// print out config changes
pub fn print_config() -> Result<(), Error> {
    eprintln!("SSH Config stanza:\n{}\n", "???"); //TODO:ssh config
    eprintln!("== Background Service ==\n{}\n", Daemon::new().render()?);
    Ok(())
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

    // TODO...
    unimplemented!()
}
