mod api;
mod auth;
mod config;
mod connect;
mod entries;
mod terminal;
mod tunnel;
mod ws;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nt", about = "Nexterm CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with a Nexterm server
    Login,
    /// Clear stored session token
    Logout,
    /// List all servers in a tree
    Ls {
        #[arg(long)] folder: Option<String>,
        #[arg(long)] tag: Option<String>,
        #[arg(long)] json: bool,
    },
    /// Connect to a server (append a command to run it non-interactively, like `ssh host "cmd"`)
    Connect {
        target: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)] command: Vec<String>,
    },
    /// Fuzzy search servers and connect
    Search {
        query: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)] command: Vec<String>,
    },
    /// Show servers and select one to connect
    Recent,
    /// Access a remote port on your local machine through a server
    Forward {
        /// Server ID or name
        target: String,
        /// Local port to listen on (defaults to same as --port)
        #[arg(short, long)]
        local: Option<u16>,
        /// Remote host to connect to (default: 127.0.0.1)
        #[arg(short, long, default_value = "127.0.0.1")]
        remote: String,
        /// Remote port to expose locally
        #[arg(short = 'p', long)]
        port: u16,
    },
    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    Set { key: String, value: String },
    Get { key: String },
    Show,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cmd_of(args: &[&str]) -> Vec<String> {
        match Cli::parse_from(args).command {
            Commands::Connect { command, .. } => command,
            _ => panic!("not connect"),
        }
    }
    #[test]
    fn parses_ssh_like_forms() {
        assert!(cmd_of(&["nt", "connect", "1"]).is_empty());          // interactive
        assert_eq!(cmd_of(&["nt", "connect", "1", "ls"]), ["ls"]);     // bare
        assert_eq!(cmd_of(&["nt", "connect", "1", "ls -la /tmp"]), ["ls -la /tmp"]); // quoted
        assert_eq!(cmd_of(&["nt", "connect", "1", "ls", "-la"]), ["ls", "-la"]);     // hyphen flags
        assert_eq!(cmd_of(&["nt", "connect", "1", "--", "ls", "-la"]), ["ls", "-la"]); // legacy --
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Login => auth::login().await,
        Commands::Logout => auth::logout(),
        Commands::Ls { folder, tag, json } => entries::list(folder, tag, json).await,
        Commands::Connect { target, command } => {
            if command.is_empty() { connect::interactive(&target).await }
            else { connect::exec(&target, &command.join(" ")).await }
        }
        Commands::Search { query, command } => {
            let cmd = if command.is_empty() { None } else { Some(command.join(" ")) };
            entries::search(&query, cmd.as_deref()).await
        }
        Commands::Recent => entries::recent().await,
        Commands::Forward { target, local, remote, port } => {
            tunnel::forward(&target, local.unwrap_or(port), &remote, port).await
        }
        Commands::Config { action } => match action {
            ConfigAction::Set { key, value } => config::set(&key, &value),
            ConfigAction::Get { key } => config::get(&key),
            ConfigAction::Show => config::show(),
        },
    }
}
