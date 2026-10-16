//! The daemon entry point.

use std::sync::Arc;

use clap::Parser;
use solstice::cli::{Cli, Command};
use solstice::config::Config;
use solstice::management::{self, ClientError, Request};
use solstice::supervisor::{build_host, Supervisor};
use solstice_gamestream::crypto::certs::{ClientStore, HostIdentity};
use solstice_gamestream::crypto::pairing::is_plausible_pin;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = if cli.config.exists() {
        Config::load(&cli.config)?
    } else {
        tracing::warn!(path = %cli.config.display(), "no config file; using defaults");
        Config::default()
    };
    let socket = config.server.control_socket();
    let remote = |request: Request| management::call(&socket, &request, &mut std::io::stdout());

    match cli.command {
        Command::Run => {
            let identity =
                HostIdentity::load_or_generate(&config.server.state_dir, &config.server.name)?;
            let clients = ClientStore::load(config.server.state_dir.join("clients.tsv"))?;
            let host = Arc::new(build_host(&config, identity, clients));
            let backend = solstice::backend_factory::build(&config)?;
            let supervisor = Supervisor::new(config, host, backend);
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async move {
                tokio::select! {
                    result = supervisor.run() => result.map_err(Into::into),
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("shutting down");
                        Ok(())
                    }
                }
            })
        }
        Command::Pair { pin, window } => {
            // Checked here as well as in the daemon, so that a PIN with a space
            // in it is reported as a bad PIN rather than a bad request.
            if !is_plausible_pin(&pin) {
                return Err("the PIN is the four digits the client is showing".into());
            }
            Ok(remote(Request::Pair {
                pin,
                window: window.map(Into::into),
            })?)
        }
        Command::Status => Ok(remote(Request::Status)?),
        // These two have an answer without a daemon -- the client list is a
        // file -- and revoking a client while the daemon is down is exactly
        // when it is safe to edit that file.
        Command::ListClients => match remote(Request::ListClients) {
            Err(ClientError::NotRunning(_)) => {
                let store = offline_store(&config)?;
                let lines = management::client_lines(&store);
                if lines.is_empty() {
                    println!("no paired clients");
                }
                for line in lines {
                    println!("{line}");
                }
                Ok(())
            }
            other => Ok(other?),
        },
        Command::Revoke { prefix } => match remote(Request::Revoke {
            prefix: prefix.clone(),
        }) {
            Err(ClientError::NotRunning(_)) => {
                let mut store = offline_store(&config)?;
                let client = management::find_client(&store, &prefix)?.clone();
                store.remove(&client.cert_der)?;
                println!(
                    "revoked {} ({})",
                    management::printable(&client.device_name),
                    &management::fingerprint(&client.cert_der)[..16]
                );
                Ok(())
            }
            other => Ok(other?),
        },
    }
}

fn offline_store(config: &Config) -> Result<ClientStore, Box<dyn std::error::Error>> {
    let path = config.server.state_dir.join("clients.tsv");
    tracing::info!(path = %path.display(), "solstice is not running; using the client list directly");
    Ok(ClientStore::load(path)?)
}
