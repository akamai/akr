use clap::Parser;
use clap::builder::styling::{Styles, AnsiColor, Effects, Style};

/// Akamai MFA CLI and SSH Agent
#[derive(Parser)]
#[clap(
    version = "1.1.2",
    author = "Akamai MFA <mfa.akamai.com/help>",
    name = "akr - Akamai Krypton"
)]
#[clap(styles = CARGO_STYLING)]
pub struct Opts {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Parser)]
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

#[derive(Parser)]
pub struct SetupArgs {
    /// a custom path for the ssh config to update
    /// omit for default "~/.ssh/config"
    #[clap(long)]
    pub ssh_config_path: Option<String>,

    /// Only print out the config changes without making them
    #[clap(long)]
    pub print_only: bool,
}


// Clap v4 removed help styling.
// In migrating from v3 to v4, this manual styling, based on how cargo styles 
// its help output was added to restore the prior aesthetic of our help page.

const HEADER: Style = AnsiColor::Green.on_default().effects(Effects::BOLD);
const USAGE: Style = AnsiColor::Green.on_default().effects(Effects::BOLD);
const LITERAL: Style = AnsiColor::Cyan.on_default().effects(Effects::BOLD);
const PLACEHOLDER: Style = AnsiColor::Cyan.on_default();
const ERROR: Style = AnsiColor::Red.on_default().effects(Effects::BOLD);
const VALID: Style = AnsiColor::Cyan.on_default().effects(Effects::BOLD);
const INVALID: Style = AnsiColor::Yellow.on_default().effects(Effects::BOLD);


/// Cargo's color style
/// [source](https://github.com/crate-ci/clap-cargo/blob/master/src/style.rs)
const CARGO_STYLING: Styles = Styles::styled()
    .header(HEADER)
    .usage(USAGE)
    .literal(LITERAL)
    .placeholder(PLACEHOLDER)
    .error(ERROR)
    .valid(VALID)
    .invalid(INVALID);