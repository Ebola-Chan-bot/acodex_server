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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Instant; // 仅调试用
use std::{io::ErrorKind, net::Ipv4Addr, sync::Arc};
use std::io::Write;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use handlers::*;
use types::Sessions;

static DEFAULT_COMMAND: OnceLock<String> = OnceLock::new();
static STATUS_HIT_LOGGED: AtomicBool = AtomicBool::new(false); // 仅调试用
static ROOT_HIT_LOGGED: AtomicBool = AtomicBool::new(false); // 仅调试用

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
    let server_started_at = Instant::now(); // 仅调试用
    eprintln!( // 仅调试用
        "[axs:start-server-begin,pid={},host={},port={},allow_any_origin={},default_command={}]", // 仅调试用
        std::process::id(), // 仅调试用
        host, // 仅调试用
        port, // 仅调试用
        allow_any_origin, // 仅调试用
        get_default_command().unwrap_or("<none>"), // 仅调试用
    ); // 仅调试用

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
            if !ROOT_HIT_LOGGED.swap(true, Ordering::Relaxed) { // 仅调试用
                eprintln!("[axs:root-first-hit,pid={}]", std::process::id()); // 仅调试用
            } // 仅调试用
            "Rust based AcodeX server"
        }))
        .route("/terminals", post(create_terminal))
        .route("/terminals/{pid}/resize", post(resize_terminal))
        .route("/terminals/{pid}", get(terminal_websocket))
        .route("/terminals/{pid}/terminate", post(terminate_terminal))
        .route("/execute-command", post(execute_command))
        .route("/status", get({ // 仅调试用
            let server_started_at = server_started_at; // 仅调试用
            move || async move { // 仅调试用
                if !STATUS_HIT_LOGGED.swap(true, Ordering::Relaxed) { // 仅调试用
                    eprintln!( // 仅调试用
                        "[axs:status-first-hit,pid={},elapsed_ms={}]", // 仅调试用
                        std::process::id(), // 仅调试用
                        server_started_at.elapsed().as_millis(), // 仅调试用
                    ); // 仅调试用
                } // 仅调试用
                "OK" // 仅调试用
            } // 仅调试用
        })) // 仅调试用
        .with_state(sessions)
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let addr: std::net::SocketAddr = (host, port).into();

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            eprintln!( // 仅调试用
                "[axs:bind-ok,pid={},addr={},elapsed_ms={}]", // 仅调试用
                std::process::id(), // 仅调试用
                listener.local_addr().unwrap(), // 仅调试用
                server_started_at.elapsed().as_millis(), // 仅调试用
            ); // 仅调试用
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
                eprintln!( // 仅调试用
                    "[axs:serve-error,pid={},error={}]", // 仅调试用
                    std::process::id(), // 仅调试用
                    e, // 仅调试用
                ); // 仅调试用
                tracing::error!("Server error: {}", e);
            }
        }
        Err(e) => {
            eprintln!( // 仅调试用
                "[axs:bind-failed,pid={},kind={:?},error={}]", // 仅调试用
                std::process::id(), // 仅调试用
                e.kind(), // 仅调试用
                e, // 仅调试用
            ); // 仅调试用
            if e.kind() == ErrorKind::AddrInUse {
                tracing::error!("Port is already in use please kill all other instances of axs server or stop any other process or app that maybe be using port {}", port);
            } else {
                tracing::error!("Failed to bind: {}", e);
            }
        }
    }
}
