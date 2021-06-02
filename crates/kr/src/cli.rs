use clap::Clap;

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap)]
#[clap(version = "1.0")]
pub struct Opts {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap)]
pub enum Command {
    /// start the ssh-agent daemon
    Start,
    /// pair with your phone/tablet
    Pair,
    /// load keys from the Akamai MFA app on your phone/tablet
    Load,
    /// generate a new credential
    Generate {
        /// a common name for the credential
        #[clap(long)]
        name: String,
    },
}
