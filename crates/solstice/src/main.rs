//! The daemon entry point.

use std::sync::Arc;

use clap::Parser;
use solstice::cli::{Cli, Command};
use solstice::config::Config;
use solstice::supervisor::{build_host, Supervisor};
use solstice_gamestream::crypto::certs::{ClientStore, HostIdentity};

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
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

    let identity = HostIdentity::load_or_generate(&config.server.state_dir, &config.server.name)?;
    let clients = ClientStore::load(config.server.state_dir.join("clients.tsv"))?;
    let host = Arc::new(build_host(&config, identity, clients));

    let runtime = tokio::runtime::Runtime::new()?;
    match cli.command {
        Command::Run => {
            let backend = solstice::backend_factory::build(&config)?;
            let supervisor = Supervisor::new(config, host, backend);
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
            // Pairing happens inside a running daemon; this process opening a
            // window of its own would pair against its own state and then exit.
            // Until there is a management socket, say so plainly rather than
            // appearing to work.
            let _ = (pin, window, host);
            Err(
                "`solstice pair` needs the management socket, which is not implemented yet; \
                 see the README's status section"
                    .into(),
            )
        }
        Command::ListClients => {
            let listed: Vec<String> = {
                let clients = host.clients.read().expect("client store lock");
                clients
                    .clients()
                    .map(|c| {
                        format!(
                            "{}  {}  {}",
                            &hex::encode(&c.cert_der)[..16],
                            c.device_name,
                            c.unique_id
                        )
                    })
                    .collect()
            };
            if listed.is_empty() {
                println!("no paired clients");
            }
            for line in listed {
                println!("{line}");
            }
            Ok(())
        }
        Command::Revoke { prefix } => {
            let target: Option<Vec<u8>> = {
                let clients = host.clients.read().expect("client store lock");
                let found = clients
                    .clients()
                    .find(|c| hex::encode(&c.cert_der).starts_with(&prefix))
                    .map(|c| c.cert_der.clone());
                found
            };
            match target {
                Some(der) if host.revoke(&der) => {
                    println!("revoked");
                    Ok(())
                }
                _ => Err(format!("no paired client matches {prefix}").into()),
            }
        }
    }
}
