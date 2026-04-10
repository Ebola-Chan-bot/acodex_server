mod handlers;
// Not gated with #[cfg(target_os)] — this crate exclusively targets
// Linux/Android and will never be built for other platforms.
mod pty_fallback;
mod scrollback;
mod types;

use axum::{
    routing::{get, post},
    Router,
};

use axum::http::HeaderValue;
use dashmap::DashMap;
use std::env;
use std::sync::OnceLock;
use std::{io::ErrorKind, net::Ipv4Addr, sync::Arc};
use std::io::Write;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use handlers::*;
use types::Sessions;

static DEFAULT_COMMAND: OnceLock<String> = OnceLock::new();

pub fn set_default_command(cmd: String) {
    let _ = DEFAULT_COMMAND.set(cmd);
}

pub fn get_default_command() -> Option<&'static str> {
    DEFAULT_COMMAND.get().map(|s| s.as_str())
}

fn should_enable_terminal_tracing() -> bool {
    if env::var_os("RUST_LOG").is_some() {
        return true;
    }

    matches!(
        env::var("AXS_TERMINAL_LOG").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("True")
    )
}

pub async fn start_server(host: Ipv4Addr, port: u16, allow_any_origin: bool) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "off".into());

    if should_enable_terminal_tracing() {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink))
            .init();
    }

    let sessions: Sessions = Arc::new(DashMap::new());

    let cors = if allow_any_origin {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let localhost = "https://localhost"
            .parse::<HeaderValue>()
            .expect("valid origin");
        CorsLayer::new()
            .allow_origin(localhost)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    let app = Router::new()
        .route("/", get(|| async {
            "Rust based AcodeX server"
        }))
        .route("/terminals", post(create_terminal))
        .route("/terminals/{pid}/resize", post(resize_terminal))
        .route("/terminals/{pid}", get(terminal_websocket))
        .route("/terminals/{pid}/terminate", post(terminate_terminal))
        .route("/execute-command", post(execute_command))
        .with_state(sessions)
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let addr: std::net::SocketAddr = (host, port).into();

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            tracing::info!("listening on {}", listener.local_addr().unwrap());

            // Notify parent process via FIFO that the server is ready to accept
            // connections. The parent shell creates a named pipe and sets
            // AXS_READY_PIPE; we write "READY\n" and close. The parent's blocking
            // `read` returns immediately — no HTTP polling needed.
            if let Ok(pipe_path) = env::var("AXS_READY_PIPE") {
                match std::fs::OpenOptions::new().write(true).open(&pipe_path) {
                    Ok(mut f) => {
                        let _ = f.write_all(b"READY\n");
                    }
                    Err(e) => {
                        eprintln!("[axs:ready-pipe-error,path={},error={}]", pipe_path, e);
                    }
                }
            }

            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("Server error: {}", e);
            }
        }
        Err(e) => {
            if e.kind() == ErrorKind::AddrInUse {
                tracing::error!("Port is already in use please kill all other instances of axs server or stop any other process or app that maybe be using port {}", port);
            } else {
                tracing::error!("Failed to bind: {}", e);
            }
        }
    }
}
