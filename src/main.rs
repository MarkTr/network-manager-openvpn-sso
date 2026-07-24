// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

mod config;
mod dbus;
mod oauth;
mod openvpn;
mod secrets;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "nm-openvpn-sso-service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Internal: open a URL via the session's xdg-desktop-portal. Invoked
    /// by this same binary, re-executed as the target user (see
    /// oauth::try_open_browser) — never called directly by NetworkManager.
    #[command(hide = true)]
    OpenUrl { url: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging - try journald first, fall back to stderr
    // Default to INFO level if RUST_LOG is not set
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(filter);

    if let Ok(journald) = tracing_journald::layer() {
        subscriber.with(journald).init();
    } else {
        subscriber
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    }

    if let Some(Commands::OpenUrl { url }) = Cli::parse().command {
        return oauth::open_url_via_portal(&url).await;
    }

    info!("Starting nm-openvpn-sso-service");

    // Start the D-Bus service
    dbus::run_service().await?;

    Ok(())
}
