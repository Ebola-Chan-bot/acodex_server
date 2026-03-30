use super::get_default_command;
use super::pty_fallback::fallback_open_and_spawn;
use super::scrollback::Scrollback;
use super::types::*;
use crate::utils::parse_u16;
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    Json,
};
use futures::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use regex::Regex;
use std::io::Write;
use std::time::{Instant, SystemTime};
use std::{
    io::Read,
    path::PathBuf,
    sync::{mpsc, Arc},
    time::Duration,
};
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

#[derive(Debug, Default, Clone)] // 仅调试用
struct SessionIoStats { // 仅调试用
    pty_chunks: u64, // 仅调试用
    pty_bytes: u64, // 仅调试用
    pty_first_chunk_elapsed_ms: Option<u128>, // 仅调试用
    pty_first_preview: Option<String>, // 仅调试用
    pty_last_preview: Option<String>, // 仅调试用
    ws_input_messages: u64, // 仅调试用
    ws_input_bytes: u64, // 仅调试用
} // 仅调试用

fn preview_bytes_for_debug(data: &[u8]) -> String { // 仅调试用
    let preview = String::from_utf8_lossy(data); // 仅调试用
    let compact = preview.replace('\r', "\\r").replace('\n', "\\n"); // 仅调试用
    if compact.len() > 160 { // 仅调试用
        format!("{}...", &compact[..160]) // 仅调试用
    } else { // 仅调试用
        compact // 仅调试用
    } // 仅调试用
} // 仅调试用

fn describe_wait_semantics(exit_code: Option<i32>, wait_signal: Option<i32>) -> String { // 仅调试用
    // Keep 182 interpretation in one place so the investigation stops treating
    // `128 + 54` as automatic proof. We need to separate "wait observed SIG54"
    // from "some inner layer returned a plain exit code 182" in every log line. 仅调试用
    let inferred_signal = exit_code.and_then(|code| (code > 128).then_some(code - 128)); // 仅调试用
    let termination_kind = if wait_signal.is_some() { // 仅调试用
        "signaled" // 仅调试用
    } else if exit_code.is_some() { // 仅调试用
        "exited" // 仅调试用
    } else { // 仅调试用
        "unknown" // 仅调试用
    }; // 仅调试用
    let signal_consistency = match (wait_signal, inferred_signal) { // 仅调试用
        (Some(wait), Some(inferred)) if wait == inferred => "match", // 仅调试用
        (Some(_), Some(_)) => "mismatch", // 仅调试用
        (Some(_), None) => "wait-only", // 仅调试用
        (None, Some(_)) => "exit-only", // 仅调试用
        (None, None) => "n/a", // 仅调试用
    }; // 仅调试用
    format!( // 仅调试用
        "wait_semantics=termination_kind={} wait_signal={} inferred_signal={} signal_consistency={}", // 仅调试用
        termination_kind, // 仅调试用
        wait_signal.map(|signal| signal.to_string()).unwrap_or_else(|| "<none>".to_string()), // 仅调试用
        inferred_signal.map(|signal| signal.to_string()).unwrap_or_else(|| "<none>".to_string()), // 仅调试用
        signal_consistency, // 仅调试用
    ) // 仅调试用
} // 仅调试用

pub struct TerminalSession {
    pub master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    pub child_killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    pub writer: Arc<Mutex<Box<dyn Write + Send>>>,
    pub scrollback: Arc<Scrollback>,
    pub output_tx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    pub exit_status: Arc<std::sync::Mutex<Option<bool>>>,
    pub exit_detail: Arc<std::sync::Mutex<Option<ProcessExitMessage>>>, // 仅调试用
    pub launch_detail: Arc<String>, // 仅调试用
    pub io_stats: Arc<std::sync::Mutex<SessionIoStats>>, // 仅调试用
    pub exit_notify: Arc<tokio::sync::Notify>,
    pub last_accessed: Arc<Mutex<SystemTime>>,
}

pub async fn create_terminal(
    State(sessions): State<Sessions>,
    Json(options): Json<TerminalOptions>,
) -> impl IntoResponse {
    let launch_started_at = Instant::now(); // 仅调试用
    let rows = parse_u16(&options.rows, "rows").expect("failed");
    let cols = parse_u16(&options.cols, "cols").expect("failed");
    tracing::info!("Creating new terminal with cols={}, rows={}", cols, rows);

    let mut program = String::from("login");
    let mut args: Vec<String> = Vec::new();
    if let Some(cmd) = get_default_command() {
        let parts: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
        if !parts.is_empty() {
            program = parts[0].clone();
            if parts.len() > 1 {
                args = parts[1..].to_vec();
            }
        }
    }

    let mut pty_backend = String::from("portable_pty"); // 仅调试用
    let mut pty_open_error = String::new(); // 仅调试用
    let mut pty_backend_detail = String::from("<none>"); // 仅调试用
    let size = PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };

    // --- Try the standard portable-pty path first ---
    let pty_system = native_pty_system();
    let openpty_result = pty_system.openpty(size);

    let std_result = match openpty_result {
        Ok(pair) => {
            let mut cmd = CommandBuilder::new(&program);
            if !args.is_empty() {
                let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                cmd.args(arg_refs);
            }
            match pair.slave.spawn_command(cmd) {
                Ok(child) => Ok((pair.master, child)),
                Err(e) => {
                    // openpty succeeded but spawn failed — this is a command
                    // error (e.g. missing program), not a PTY capability issue.
                    // Do NOT fall back; report immediately.
                    tracing::error!("spawn_command failed: {}", e);
                    return Json(ErrorResponse {
                        error: format!("Failed to spawn command: {e}"),
                    })
                    .into_response();
                }
            }
        }
        Err(e) => Err(e),
    };

    // --- If openpty itself failed, fall back to TIOCGPTPEER ---
    let (master, mut child) = match std_result {
        Ok(pair) => pair,
        Err(e) => {
            pty_backend = String::from("tiocgptpeer_fallback"); // 仅调试用
            pty_open_error = e.to_string(); // 仅调试用
            tracing::warn!(
                "Standard openpty failed ({}), trying TIOCGPTPEER fallback",
                e
            );
            match fallback_open_and_spawn(size, &program, &args) {
                Ok((master, child, detail)) => { // 仅调试用
                    pty_backend_detail = detail; // 仅调试用
                    tracing::info!( // 仅调试用
                        "TIOCGPTPEER fallback ready backend_detail={}", // 仅调试用
                        pty_backend_detail, // 仅调试用
                    ); // 仅调试用
                    (master, child) // 仅调试用
                }
                Err(fb_err) => {
                    tracing::error!("TIOCGPTPEER fallback also failed: {}", fb_err);
                    return Json(ErrorResponse {
                        error: format!("Failed to open PTY: {e}; TIOCGPTPEER fallback: {fb_err}"),
                    })
                    .into_response();
                }
            }
        }
    };

    // --- Common session setup ---
    let pid = child.process_id().unwrap_or(0);
    let launch_detail = Arc::new(format!( // 仅调试用
        "program={} args={} pty_backend={} openpty_error={} backend_detail={} cols={} rows={} launch_elapsed_ms={}", // 仅调试用
        program, // 仅调试用
        serde_json::to_string(&args).unwrap_or_else(|_| "[]".to_string()), // 仅调试用
        pty_backend, // 仅调试用
        if pty_open_error.is_empty() { "<none>".to_string() } else { pty_open_error }, // 仅调试用
        pty_backend_detail, // 仅调试用
        cols, // 仅调试用
        rows, // 仅调试用
        launch_started_at.elapsed().as_millis(), // 仅调试用
    )); // 仅调试用
    tracing::info!("Terminal created successfully with PID: {} ({})", pid, launch_detail.as_ref()); // 仅调试用

    let reader = match master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to clone PTY reader: {}", e);
            let _ = child.kill();
            let _ = child.wait();
            return Json(ErrorResponse {
                error: format!("Failed to clone PTY reader: {e}"),
            })
            .into_response();
        }
    };
    let writer = match master.take_writer() {
        Ok(w) => Arc::new(Mutex::new(w)),
        Err(e) => {
            tracing::error!("Failed to take PTY writer: {}", e);
            let _ = child.kill();
            let _ = child.wait();
            return Json(ErrorResponse {
                error: format!("Failed to take PTY writer: {e}"),
            })
            .into_response();
        }
    };
    let master: Arc<Mutex<Box<dyn MasterPty + Send>>> = Arc::new(Mutex::new(master));
    let child_killer = Arc::new(Mutex::new(child.clone_killer()));

    let scrollback = Arc::new(Scrollback::new(pid));
    let output_tx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let exit_status: Arc<std::sync::Mutex<Option<bool>>> = Arc::new(std::sync::Mutex::new(None));
    let exit_detail: Arc<std::sync::Mutex<Option<ProcessExitMessage>>> = // 仅调试用
        Arc::new(std::sync::Mutex::new(None)); // 仅调试用
    let io_stats: Arc<std::sync::Mutex<SessionIoStats>> = // 仅调试用
        Arc::new(std::sync::Mutex::new(SessionIoStats::default())); // 仅调试用
    let exit_notify = Arc::new(tokio::sync::Notify::new());

    // Background PTY reader — runs for the session lifetime
    {
        let scrollback = scrollback.clone();
        let output_tx = output_tx.clone();
        let io_stats = io_stats.clone(); // 仅调试用
        let pty_reader_started_at = launch_started_at; // 仅调试用
        spawn_blocking(move || {
            let mut reader = reader;
            let mut read_buffer = [0u8; 8192];
            let reader_exit_reason; // 仅调试用
            loop {
                let n = match reader.read(&mut read_buffer) {
                    Ok(n) => { // 仅调试用
                        if n == 0 { // 仅调试用
                            reader_exit_reason = String::from("eof"); // 仅调试用
                            break; // 仅调试用
                        } // 仅调试用
                        n // 仅调试用
                    } // 仅调试用
                    Err(error) => { // 仅调试用
                        reader_exit_reason = format!("read_error={}", error); // 仅调试用
                        break; // 仅调试用
                    } // 仅调试用
                };

                let data = &read_buffer[..n];
                let _ = scrollback.append(data);

                { // 仅调试用
                    let mut stats = io_stats.lock().unwrap(); // 仅调试用
                    stats.pty_chunks += 1; // 仅调试用
                    stats.pty_bytes += u64::try_from(n).unwrap_or(u64::MAX); // 仅调试用
                    let preview = preview_bytes_for_debug(data); // 仅调试用
                    if stats.pty_first_preview.is_none() { // 仅调试用
                        // 这里单独记录首个 PTY 字节到达时间，是为了区分“shell 尚未产出首屏输出”和“首屏输出已经出现，但 WS 还没接管导致丢了回放”两类根因。当前 MOTD 丢失现象只看前端首帧不够，需要以后端 PTY 首字节为准。 仅调试用
                        let first_chunk_elapsed_ms = pty_reader_started_at.elapsed().as_millis(); // 仅调试用
                        stats.pty_first_chunk_elapsed_ms = Some(first_chunk_elapsed_ms); // 仅调试用
                        stats.pty_first_preview = Some(preview.clone()); // 仅调试用
                        tracing::warn!( // 仅调试用
                            "PTY first output pid={} elapsed_ms={} bytes={} preview={}", // 仅调试用
                            pid, // 仅调试用
                            first_chunk_elapsed_ms, // 仅调试用
                            n, // 仅调试用
                            preview, // 仅调试用
                        ); // 仅调试用
                    } // 仅调试用
                    stats.pty_last_preview = Some(preview); // 仅调试用
                } // 仅调试用

                if let Ok(guard) = output_tx.try_lock() {
                    if let Some(ref tx) = *guard {
                        let _ = tx.try_send(data.to_vec());
                    }
                }
            }
            let final_stats = io_stats.lock().unwrap().clone(); // 仅调试用
            // 这里补充 PTY reader 退出原因，是为了把“WebSocket 已连上但从未出现首包输出”的情况继续细分成 EOF、read error 或其他读循环终止。当前 60981 案例已经证明前端没有收到任何数据，下一步必须确认后端 PTY 是否在首包前就结束读取。 仅调试用
            tracing::warn!( // 仅调试用
                "Background PTY reader exited for PID {} reason={} elapsed_ms={} io_stats={:?}", // 仅调试用
                pid, // 仅调试用
                reader_exit_reason, // 仅调试用
                pty_reader_started_at.elapsed().as_millis(), // 仅调试用
                final_stats, // 仅调试用
            ); // 仅调试用
        });
    }

    // Background child waiter — signals when process exits
    {
        let exit_status = exit_status.clone();
        let exit_detail = exit_detail.clone(); // 仅调试用
        let launch_detail_for_waiter = launch_detail.clone(); // 仅调试用
        let scrollback_for_waiter = scrollback.clone(); // 仅调试用: capture PTY output on exit
        let io_stats_for_waiter = io_stats.clone(); // 仅调试用
        let sessions_for_waiter = sessions.clone(); // 仅调试用: signal 54 forensics — log concurrent session state on abnormal exit
        let child_started_at = Instant::now(); // 仅调试用
        let exit_notify = exit_notify.clone();
        let child = Arc::new(std::sync::Mutex::new(child));
        spawn_blocking(move || {
            let mut child_guard = child.lock().unwrap();
            let success = match child_guard.wait() {
                Ok(status) => {
                    let runtime_ms = child_started_at.elapsed().as_millis(); // 仅调试用
                    // 仅调试用: give PTY reader a moment to flush remaining output to scrollback,
                    // then capture the tail for diagnostics (critical for exit_code=182 where bash
                    // dies before producing any visible output)
                    std::thread::sleep(Duration::from_millis(200));
                    let scrollback_preview = scrollback_for_waiter // 仅调试用
                        .read_tail_and_then(2048, || ()) // 仅调试用
                        .map(|(data, _)| { // 仅调试用
                            let s = String::from_utf8_lossy(&data); // 仅调试用
                            if s.len() > 512 { // 仅调试用
                                format!("...{}", &s[s.len() - 512..]) // 仅调试用
                            } else { // 仅调试用
                                s.to_string() // 仅调试用
                            } // 仅调试用
                        }) // 仅调试用
                        .unwrap_or_else(|_| "<read_error>".to_string()); // 仅调试用
                    let exit_code = Some(i32::try_from(status.exit_code()).unwrap_or(i32::MAX)); // 仅调试用
                    let wait_signal = status.signal().and_then(|signal| signal.parse::<i32>().ok()); // 仅调试用
                    let wait_semantics = describe_wait_semantics(exit_code, wait_signal); // 仅调试用
                    let exit_message = ProcessExitMessage { // 仅调试用
                        exit_code, // 仅调试用
                        signal: wait_signal.map(|signal| signal.to_string()), // 仅调试用
                        message: format!( // 仅调试用
                            "wait_status={} {} runtime_ms={} launch_detail={} scrollback_preview={} io_stats={:?}", // 仅调试用
                            status, // 仅调试用
                            wait_semantics, // 仅调试用
                            runtime_ms, // 仅调试用
                            launch_detail_for_waiter.as_ref(), // 仅调试用
                            scrollback_preview, // 仅调试用
                            io_stats_for_waiter.lock().unwrap().clone(), // 仅调试用
                        ), // 仅调试用
                    }; // 仅调试用
                    tracing::warn!( // 仅调试用
                        "Terminal wait semantics pid={} {}", // 仅调试用
                        pid, // 仅调试用
                        wait_semantics, // 仅调试用
                    ); // 仅调试用
                    // Keep a dedicated structured log here because the WebSocket exit event can be
                    // observed later than the child waiter and may be truncated or normalized by
                    // intermediate layers. This line preserves the exact backend-side exit detail
                    // for the specific immediate-exit case where the terminal dies before any
                    // bootstrap frame becomes visible on the client. 仅调试用
                    tracing::warn!( // 仅调试用
                        "Terminal process exit detail pid={} exit_code={:?} signal={:?} message={}", // 仅调试用
                        pid, // 仅调试用
                        exit_message.exit_code, // 仅调试用
                        exit_message.signal, // 仅调试用
                        exit_message.message, // 仅调试用
                    ); // 仅调试用
                    // 仅调试用: signal 54 forensics — when exit_code > 128, log concurrent
                    // session count, all active PIDs, and axs process signal state from
                    // /proc/self/status to identify who sent signal 54 and what the
                    // race condition involves.
                    if let Some(ec) = exit_message.exit_code { // 仅调试用
                        if ec > 128 || wait_signal.is_some() { // 仅调试用
                            let active_pids: Vec<u32> = sessions_for_waiter // 仅调试用
                                .iter() // 仅调试用
                                .map(|r| *r.key()) // 仅调试用
                                .collect(); // 仅调试用
                            let axs_sig_status = std::fs::read_to_string("/proc/self/status") // 仅调试用
                                .unwrap_or_default() // 仅调试用
                                .lines() // 仅调试用
                                .filter(|l| l.starts_with("Sig") || l.starts_with("Name") || l.starts_with("Pid") || l.starts_with("PPid") || l.starts_with("Tgid")) // 仅调试用
                                .collect::<Vec<&str>>() // 仅调试用
                                .join(" | "); // 仅调试用
                            tracing::warn!( // 仅调试用
                                "Signal forensics pid={} exit_code={} wait_signal={:?} concurrent_sessions={} active_pids={:?} axs_proc_status=[{}]", // 仅调试用
                                pid, ec, wait_signal, sessions_for_waiter.len(), active_pids, axs_sig_status, // 仅调试用
                            ); // 仅调试用
                        } // 仅调试用
                    } // 仅调试用
                    let success = status.success();
                    *exit_detail.lock().unwrap() = Some(exit_message); // 仅调试用
                    success
                }
                Err(error) => {
                    *exit_detail.lock().unwrap() = Some(ProcessExitMessage { // 仅调试用
                        exit_code: None, // 仅调试用
                        signal: None, // 仅调试用
                        message: format!("wait_error={} runtime_ms={} launch_detail={} io_stats={:?}", error, child_started_at.elapsed().as_millis(), launch_detail_for_waiter.as_ref(), io_stats_for_waiter.lock().unwrap().clone()), // 仅调试用
                    }); // 仅调试用
                    false
                }
            };
            *exit_status.lock().unwrap() = Some(success);
            exit_notify.notify_waiters();
            tracing::info!(
                "Background child waiter exited for PID {} (success={}, detail={:?})", // 仅调试用
                pid,
                success,
                exit_detail.lock().unwrap().as_ref() // 仅调试用
            );
        });
    }

    let session = TerminalSession {
        master,
        child_killer,
        writer,
        scrollback,
        output_tx,
        exit_status,
        exit_detail, // 仅调试用
        launch_detail: launch_detail.clone(), // 仅调试用
        io_stats, // 仅调试用
        exit_notify,
        last_accessed: Arc::new(Mutex::new(SystemTime::now())),
    };

    sessions.insert(pid, session);
    // 仅调试用: return JSON with launch_detail so frontend can log which PTY backend
    // each terminal used (critical for diagnosing intermittent fallback failures)
    Json(serde_json::json!({
        "pid": pid,
        "launch_detail": launch_detail.as_ref()
    })).into_response()
}

pub async fn resize_terminal(
    State(sessions): State<Sessions>,
    Path(pid): Path<u32>,
    Json(options): Json<TerminalOptions>,
) -> impl IntoResponse {
    let rows = parse_u16(&options.rows, "rows").expect("Failed");
    let cols = parse_u16(&options.cols, "cols").expect("Failed");
    tracing::info!("Resizing terminal {} to cols={}, rows={}", pid, cols, rows);

    if let Some(session) = sessions.get(&pid) {
        let size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        match session.master.lock().await.resize(size) {
            Ok(_) => Json(serde_json::json!({"success": true})).into_response(),
            Err(e) => Json(ErrorResponse {
                error: format!("Failed to resize: {e}"),
            })
            .into_response(),
        }
    } else {
        Json(ErrorResponse {
            error: "Session not found".to_string(),
        })
        .into_response()
    }
}

pub async fn terminal_websocket(
    ws: WebSocketUpgrade,
    Path(pid): Path<u32>,
    State(sessions): State<Sessions>,
) -> impl IntoResponse {
    tracing::info!("WebSocket connection request for terminal {}", pid);
    ws.on_upgrade(move |socket| handle_socket(socket, pid, sessions))
}

async fn handle_socket(socket: WebSocket, pid: u32, sessions: Sessions) {
    let (mut sender, mut receiver) = socket.split();

    let (writer, scrollback, output_tx_arc, exit_status_arc, exit_detail_arc, launch_detail, io_stats_arc, exit_notify) = {
        let Some(session) = sessions.get(&pid) else {
            tracing::error!("Session {} not found", pid);
            return;
        };

        *session.last_accessed.lock().await = SystemTime::now();
        tracing::info!("WebSocket connection established for terminal {}", pid);

        (
            session.writer.clone(),
            session.scrollback.clone(),
            session.output_tx.clone(),
            session.exit_status.clone(),
            session.exit_detail.clone(), // 仅调试用
            session.launch_detail.clone(), // 仅调试用
            session.io_stats.clone(), // 仅调试用
            session.exit_notify.clone(),
        )
    };

    let build_exit_message = || { // 仅调试用
        let stored_detail = { // 仅调试用
            let guard = exit_detail_arc.lock().unwrap(); // 仅调试用
            guard.as_ref().map(|detail| ProcessExitMessage { // 仅调试用
                exit_code: detail.exit_code, // 仅调试用
                signal: detail.signal.clone(), // 仅调试用
                message: detail.message.clone(), // 仅调试用
            }) // 仅调试用
        }; // 仅调试用
        if let Some(detail) = stored_detail { // 仅调试用
            return detail; // 仅调试用
        } // 仅调试用

        let success = exit_status_arc.lock().unwrap().unwrap_or(false); // 仅调试用
        ProcessExitMessage { // 仅调试用
            exit_code: Some(if success { 0 } else { 1 }), // 仅调试用
            signal: None, // 仅调试用
            message: format!( // 仅调试用
                "{}; launch_detail={} io_stats={:?}", // 仅调试用
                if success { "Process exited successfully" } else { "Process exited with non-zero status" }, // 仅调试用
                launch_detail.as_ref(), // 仅调试用
                io_stats_arc.lock().unwrap().clone(), // 仅调试用
            ), // 仅调试用
        } // 仅调试用
    }; // 仅调试用

    // Check if process already exited
    let already_exited = {
        let guard = exit_status_arc.lock().unwrap();
        *guard
    };
    if let Some(_success) = already_exited {
        let exit_message = build_exit_message(); // 仅调试用
        let exit_json = serde_json::to_string(&exit_message).unwrap_or_default();
        let _ = sender
            .send(Message::Text(
                format!("{{\"type\":\"exit\",\"data\":{exit_json}}}").into(),
            ))
            .await;
        sessions.remove(&pid);
        return;
    }

    // Create output channel for this WS connection
    let (ws_output_tx, mut ws_output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // Send full scrollback history, then atomically enable live forwarding before the
    // PTY reader can append more bytes to the scrollback file. Without that ordering,
    // the first session can replay the initial MOTD from scrollback and then receive the
    // same bytes again from the live channel during the same handshake window.
    let scrollback_for_replay = scrollback.clone();
    let output_tx_for_replay = output_tx_arc.clone();
    let ws_output_tx_for_replay = ws_output_tx.clone();
    match spawn_blocking(move || {
        scrollback_for_replay.read_tail_and_then(MAX_SCROLLBACK_BYTES, || {
            let mut guard = output_tx_for_replay.lock().unwrap();
            *guard = Some(ws_output_tx_for_replay);
        })
    })
    .await
    {
        Ok(Ok((contents, _))) if !contents.is_empty() => {
            // 这里必须把 replay 字节数和当时的 PTY 统计一起打出来，否则下次再出现“只有 prompt、没有 MOTD”时，无法判断是 PTY 根本没产出，还是 PTY 已经产出但 WS 接管时只回放到了尾部。 仅调试用
            let replay_preview = preview_bytes_for_debug(&contents); // 仅调试用
            let replay_bytes = contents.len(); // 仅调试用
            let replay_stats = io_stats_arc.lock().unwrap().clone(); // 仅调试用
            tracing::warn!( // 仅调试用
                "WS replay handshake pid={} replay_bytes={} replay_preview={} io_stats={:?} launch_detail={}", // 仅调试用
                pid, // 仅调试用
                replay_bytes, // 仅调试用
                replay_preview, // 仅调试用
                replay_stats, // 仅调试用
                launch_detail.as_ref(), // 仅调试用
            ); // 仅调试用
            let _ = sender.send(Message::Binary(Bytes::from(contents))).await;
        }
        Ok(Ok((_contents, _))) => {
            // 空 replay 也必须记录，因为它和“PTY 首字节已经到达”的组合，正是判断首屏输出在订阅前后是否丢失的关键证据。 仅调试用
            tracing::warn!( // 仅调试用
                "WS replay handshake pid={} replay_bytes=0 io_stats={:?} launch_detail={}", // 仅调试用
                pid, // 仅调试用
                io_stats_arc.lock().unwrap().clone(), // 仅调试用
                launch_detail.as_ref(), // 仅调试用
            ); // 仅调试用
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to read scrollback for terminal {}: {}", pid, e);
        }
        _ => {}
    }

    // WS input → PTY writer channel
    let (ws_input_tx, ws_input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let write_handle = {
        let writer = writer.clone();
        spawn_blocking(move || {
            while let Ok(data) = ws_input_rx.recv() {
                let mut guard = writer.blocking_lock();
                if guard.write_all(&data).is_err() || guard.flush().is_err() {
                    break;
                }
            }
        })
    };

    // Main loop with output coalescing
    let mut coalesce_buf: Vec<u8> = Vec::with_capacity(16384);
    let mut interval = tokio::time::interval(Duration::from_millis(8));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if !coalesce_buf.is_empty() {
                    let frame = std::mem::replace(&mut coalesce_buf, Vec::with_capacity(16384));
                    if sender.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                        break;
                    }
                }
            }
            data = ws_output_rx.recv() => {
                match data {
                    Some(data) => {
                        coalesce_buf.extend_from_slice(&data);
                        if coalesce_buf.len() >= 8192 {
                            let frame = std::mem::replace(&mut coalesce_buf, Vec::with_capacity(16384));
                            if sender.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                                break;
                            }
                        }
                    }
                    None => {
                        if !coalesce_buf.is_empty() {
                            let _ = sender.send(Message::Binary(Bytes::from(std::mem::take(&mut coalesce_buf)))).await;
                        }
                        break;
                    }
                }
            }
            _ = exit_notify.notified() => {
                // Give the reader a moment to flush remaining output
                tokio::time::sleep(Duration::from_millis(50)).await;

                while let Ok(data) = ws_output_rx.try_recv() {
                    coalesce_buf.extend_from_slice(&data);
                }
                if !coalesce_buf.is_empty() {
                    let _ = sender.send(Message::Binary(Bytes::from(std::mem::take(&mut coalesce_buf)))).await;
                }

                let exit_message = build_exit_message(); // 仅调试用
                let exit_json = serde_json::to_string(&exit_message).unwrap_or_default();
                // Mirror the exact payload that is about to be emitted so the next reproduction can
                // distinguish backend data loss from frontend parsing/logging loss. The current
                // symptom shows only a generic exit message in the browser log even though the
                // backend child waiter builds richer detail for early exit-1 failures. 仅调试用
                tracing::warn!( // 仅调试用
                    "Sending terminal exit event pid={} payload={}", // 仅调试用
                    pid, // 仅调试用
                    exit_json, // 仅调试用
                ); // 仅调试用
                let _ = sender
                    .send(Message::Text(
                        format!("{{\"type\":\"exit\",\"data\":{exit_json}}}").into(),
                    ))
                    .await;

                sessions.remove(&pid);
                break;
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(message)) => {
                        let data = match message {
                            Message::Text(text) => text.as_bytes().to_vec(),
                            Message::Binary(data) => data.to_vec(),
                            Message::Close(_) => break,
                            _ => continue,
                        };
                        { // 仅调试用
                            let mut stats = io_stats_arc.lock().unwrap(); // 仅调试用
                            stats.ws_input_messages += 1; // 仅调试用
                            stats.ws_input_bytes += u64::try_from(data.len()).unwrap_or(u64::MAX); // 仅调试用
                        } // 仅调试用
                        if ws_input_tx.send(data).is_err() {
                            break;
                        }
                    }
                    None | Some(Err(_)) => break,
                }
            }
        }
    }

    // Disconnect: clear the output sender so background reader stops forwarding
    {
        let mut guard = output_tx_arc.lock().unwrap();
        *guard = None;
    }

    drop(ws_input_tx);
    let _ = write_handle.await;

    tracing::info!("WebSocket disconnected for terminal {}", pid);
}

pub async fn terminate_terminal(
    State(sessions): State<Sessions>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    tracing::info!("Terminating terminal {}", pid);

    if let Some((_, session)) = sessions.remove(&pid) {
        let result = session
            .child_killer
            .lock()
            .await
            .kill()
            .map_err(|e| e.to_string());

        drop(session.writer.lock().await);
        session.scrollback.cleanup();

        match result {
            Ok(_) => {
                tracing::info!("Terminal {} terminated successfully", pid);
                Json(serde_json::json!({"success": true})).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to terminate terminal {}: {}", pid, e);
                Json(ErrorResponse {
                    error: format!("Failed to terminate terminal {pid}: {e}"),
                })
                .into_response()
            }
        }
    } else {
        tracing::error!("Failed to terminate terminal {}: session not found", pid);
        Json(ErrorResponse {
            error: "Session not found".to_string(),
        })
        .into_response()
    }
}

pub async fn execute_command(Json(options): Json<ExecuteCommandOption>) -> impl IntoResponse {
    let cwd = options.cwd.or(options.u_cwd).unwrap_or("".to_string());

    tracing::info!(
        command = %options.command,
        cwd = %cwd,
        "Executing command"
    );

    let shell = String::from("sh");
    let cwd = if cwd.is_empty() {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    } else {
        PathBuf::from(cwd)
    };

    if !cwd.exists() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(CommandResponse {
                output: String::new(),
                error: Some("Working directory does not exist".to_string()),
            }),
        )
            .into_response();
    }

    let command = options.command.clone();

    let result = spawn_blocking(move || {
        let pty_system = native_pty_system();
        let size = PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = pty_system.openpty(size)?;

        let mut cmd = CommandBuilder::new(shell);
        cmd.args(["-c", &command]);
        cmd.cwd(cwd);

        let mut child = pair.slave.spawn_command(cmd)?;
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;

        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();

        let read_thread = std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(buffer[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let timeout_duration = Duration::from_secs(30);
        let start_time = SystemTime::now();
        let mut output = Vec::new();

        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(data) => {
                    output.extend(data);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if start_time.elapsed().unwrap_or_default() > timeout_duration {
                        child.kill()?;
                        return Err("Command execution timed out".into());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
        }

        drop(writer);
        let _ = read_thread.join();
        child.wait()?;

        Ok::<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>(output)
    })
    .await;

    match result {
        Ok(Ok(output)) => {
            let output_str = String::from_utf8_lossy(&output).into_owned();

            let ansi_regex =
                Regex::new(r"\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]|\x1B\[[0-9]+[A-Za-z]").unwrap();
            let cleaned_output = ansi_regex.replace_all(&output_str, "").to_string();

            tracing::info!(
                output_length = cleaned_output.len(),
                "Command completed successfully"
            );

            (
                axum::http::StatusCode::OK,
                Json(CommandResponse {
                    output: cleaned_output,
                    error: None,
                }),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("Command execution failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(CommandResponse {
                    output: String::new(),
                    error: Some(e.to_string()),
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Blocking task failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(CommandResponse {
                    output: String::new(),
                    error: Some("Internal server error".to_string()),
                }),
            )
                .into_response()
        }
    }
}
