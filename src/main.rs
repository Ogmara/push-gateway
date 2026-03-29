//! Ogmara Push Notification Gateway — entry point.
//!
//! Bridges L2 node mentions/DM notifications to platform-specific
//! push notification services (FCM, APNs, Web Push).

mod api;
mod config;
mod listener;
mod push;
mod registry;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "ogmara-push-gateway")]
#[command(about = "Ogmara push notification gateway — FCM, APNs, and Web Push bridge")]
#[command(version)]
struct Cli {
    /// Path to configuration file.
    #[arg(short, long, default_value = "push-gateway.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the gateway (default).
    Run,
    /// Generate a default configuration file.
    Init {
        #[arg(short, long, default_value = "push-gateway.toml")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Init { output } => {
            if output.exists() {
                anyhow::bail!("{} already exists", output.display());
            }
            std::fs::write(&output, config::Config::default_toml())?;
            println!("Created default config at {}", output.display());
            Ok(())
        }

        Commands::Run => {
            let cfg = config::Config::load(&cli.config)?;
            init_logging(&cfg.logging);

            info!(
                "Ogmara Push Gateway v{} starting",
                env!("CARGO_PKG_VERSION")
            );

            let registry = Arc::new(registry::DeviceRegistry::new());
            let dispatcher = Arc::new(push::PushDispatcher::new(&cfg));

            let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

            // Start WebSocket listeners for each configured L2 node
            let mut listener_tasks = Vec::new();
            for node_url in &cfg.ogmara.node_urls {
                let url = node_url.clone();
                let reg = registry.clone();
                let disp = dispatcher.clone();
                let rx = shutdown_tx.subscribe();
                listener_tasks.push(tokio::spawn(async move {
                    listener::listen_to_node(&url, reg, disp, rx).await;
                }));
            }

            // Start REST API server
            // Push secret: prefer env var, fall back to config file
            let push_secret = std::env::var("OGMARA_PUSH_SECRET")
                .unwrap_or_else(|_| cfg.gateway.push_secret.clone());

            let api_state = Arc::new(api::ApiState {
                registry: registry.clone(),
                dispatcher: dispatcher.clone(),
                push_secret,
            });
            let app = api::build_router(api_state);

            let addr: SocketAddr = format!(
                "{}:{}",
                cfg.gateway.listen_addr, cfg.gateway.listen_port
            )
            .parse()
            .context("parsing listen address")?;

            info!(addr = %addr, "API server starting");

            let listener = tokio::net::TcpListener::bind(addr).await?;
            let shutdown_rx = shutdown_tx.subscribe();

            let api_task = tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let mut rx = shutdown_rx;
                        let _ = rx.recv().await;
                    })
                    .await
                    .ok();
            });

            // Wait for Ctrl+C
            tokio::signal::ctrl_c().await?;
            info!("Shutting down...");
            let _ = shutdown_tx.send(());

            for task in listener_tasks {
                task.abort();
            }
            api_task.abort();

            info!("Push gateway stopped");
            Ok(())
        }
    }
}

fn init_logging(logging: &config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&logging.level));

    match logging.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }
}
