//! Ogmara Push Notification Gateway — entry point.
//!
//! Bridges L2 node mentions/DM notifications to platform-specific
//! push notification services (FCM, APNs, Web Push).

mod api;
mod config;
mod crypto;
mod push;
mod registry;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;
use clap::{Parser, Subcommand};
use tracing::{info, warn};

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

            // Token-at-rest encryption key (audit 2026-06-07 W3). Loaded from
            // OGMARA_REGISTRY_KEY (base64 or hex, 32 bytes). If unset/invalid we
            // log a clear warning and fall back to plaintext storage so dev
            // setups don't hard-fail — production MUST set this.
            let registry_cipher = match std::env::var("OGMARA_REGISTRY_KEY") {
                Ok(v) if !v.trim().is_empty() => {
                    match crypto::registry_crypto::RegistryCipher::from_env_value(&v) {
                        Some(c) => {
                            info!("Registry token-at-rest encryption ENABLED (OGMARA_REGISTRY_KEY)");
                            Some(c)
                        }
                        None => {
                            warn!(
                                "OGMARA_REGISTRY_KEY is set but is not a valid 32-byte \
                                 base64/hex key — storing push tokens in PLAINTEXT. Fix the key."
                            );
                            None
                        }
                    }
                }
                _ => {
                    warn!(
                        "OGMARA_REGISTRY_KEY is unset — push tokens will be stored in \
                         PLAINTEXT at rest. Set a 32-byte base64/hex key in production."
                    );
                    None
                }
            };

            // Load persistent device registry
            let registry_path = Path::new(&cfg.gateway.registry_file);
            let registry =
                Arc::new(registry::DeviceRegistry::load(registry_path, registry_cipher));

            let dispatcher = Arc::new(push::PushDispatcher::new(&cfg));

            // Derive VAPID public key for the /vapid-key endpoint
            let vapid_public_key = if cfg.webpush.enabled && !cfg.webpush.vapid_private_key.is_empty()
            {
                match BASE64URL.decode(&cfg.webpush.vapid_private_key) {
                    Ok(key_bytes) => {
                        use p256::ecdsa::SigningKey;
                        match SigningKey::from_slice(&key_bytes) {
                            Ok(sk) => {
                                let pk = sk.verifying_key();
                                let pub_bytes = pk.to_sec1_bytes();
                                let encoded = BASE64URL.encode(&pub_bytes);
                                info!(key_len = pub_bytes.len(), "VAPID public key derived");
                                encoded
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to derive VAPID public key");
                                String::new()
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to decode VAPID private key for public key derivation");
                        String::new()
                    }
                }
            } else {
                String::new()
            };

            let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

            // The L2-node WebSocket listener was removed (audit 2026-06-07 W9):
            // it was a dead stub (empty mention/DM handlers, no dispatch) that
            // held an idle reconnect loop to ws://localhost forever. Mentions/DMs
            // are delivered to this gateway via authenticated POST /push.

            // Background maintenance: debounced registry flush + stale-TTL
            // eviction sweep (audit 2026-06-07 W2). Both honor shutdown.
            let maint_registry = registry.clone();
            let mut maint_shutdown = shutdown_tx.subscribe();
            let maint_task = tokio::spawn(async move {
                let mut flush_tick = tokio::time::interval(Duration::from_secs(10));
                let mut evict_tick = tokio::time::interval(Duration::from_secs(3600));
                // Skip the immediate first tick of the eviction timer.
                evict_tick.tick().await;
                loop {
                    tokio::select! {
                        _ = flush_tick.tick() => {
                            maint_registry.flush();
                        }
                        _ = evict_tick.tick() => {
                            maint_registry.evict_stale();
                        }
                        _ = maint_shutdown.recv() => break,
                    }
                }
            });

            // Start REST API server
            // Push secret: prefer env var, fall back to config file
            let push_secret = std::env::var("OGMARA_PUSH_SECRET")
                .unwrap_or_else(|_| cfg.gateway.push_secret.clone());

            // Canonical gateway URL that registration auth signatures bind to
            // (audit 2026-06-07 host-binding). Env var overrides config; strip
            // any trailing slash so it matches the client-signed value.
            let gateway_host = std::env::var("OGMARA_GATEWAY_URL")
                .unwrap_or_else(|_| cfg.gateway.public_url.clone())
                .trim_end_matches('/')
                .to_string();
            if gateway_host.is_empty() {
                warn!(
                    "gateway.public_url / OGMARA_GATEWAY_URL is unset — device \
                     registration auth is host-bound to an empty string and will \
                     reject clients that sign their real gateway URL. Set it to \
                     this gateway's public URL."
                );
            }

            let api_state = Arc::new(api::ApiState {
                registry: registry.clone(),
                dispatcher: dispatcher.clone(),
                push_secret,
                vapid_public_key,
                gateway_host,
                nonces: api::NonceCache::new(api::NONCE_TTL_MS),
                // Per-IP rate limiter for /register + /unregister (audit
                // 2026-06-07 W1), using the previously-dead rate_limit_per_sec.
                rate_limiter: api::RateLimiter::new(cfg.gateway.rate_limit_per_sec),
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
                // `into_make_service_with_connect_info` exposes the peer
                // SocketAddr to the rate-limit middleware via ConnectInfo
                // (audit 2026-06-07 W1).
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
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

            // Flush any unpersisted registry changes before exit (audit
            // 2026-06-07 W2 — persistence is debounced).
            registry.flush();

            maint_task.abort();
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
