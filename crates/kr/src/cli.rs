use clap::Clap;

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap)]
#[clap(
    version = "1.1.0",
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
    /// Pair with your phone/tablet
    Pair {
        /// Run the setup step before pairing
        #[clap(long)]
        setup: bool,
    },
    /// Load keys from the Akamai MFA app on your phone/tablet
    Load,
    /// Generate a new SSH credential
    Generate {
        /// a common name for the credential
        #[clap(long)]
        name: String,
    },
    /// Setup the background daemon and ssh configuration
    Setup(SetupArgs),

    /// Start the ssh-agent daemon
    /// Note: don't run this manually, see `setup` to
    /// install this as a background service
    Start,
    /// Get pairing info from your phone/tablet
    Status,
    /// Health check of all the dep systems and system configs
    Check,
    /// Unpair from your phone/tablet
    Unpair,
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
