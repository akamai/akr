use clap::Clap;

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap)]
#[clap(
    version = "1.0",
    author = "Akamai MFA <mfa.akamai.com/help>",
    name = "akr - Akamai Krypton"
)]
#[clap(setting = clap::AppSettings::ColoredHelp)]
pub struct Opts {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap)]
pub enum Command {
    /// pair with your phone/tablet
    Pair,
    /// load keys from the Akamai MFA app on your phone/tablet
    Load,
    /// generate a new SSH credential
    Generate {
        /// a common name for the credential
        #[clap(long)]
        name: String,
    },
    /// Setup the background daemon and ssh configuration
    Setup(SetupArgs),

    /// start the ssh-agent daemon
    /// Note: don't run this manually, see `setup` to
    /// install this as a background service
    Start,
}

#[derive(Clap)]
pub struct SetupArgs {
    /// a custom path for the ssh config to update
    /// omit for default "~/.ssh/config"
    #[clap(long)]
    pub ssh_config_path: Option<String>,

    /// Only print out the config changes without making them
    #[clap(long)]
    pub print_only: bool,
}
