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
    Start,
    Pair,
    Generate {
        #[clap(long)]
        name: String,

        #[clap(long)]
        path: String,
    },
}
