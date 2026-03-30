use anyhow::{Context, bail};
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub enum ExecProbeOutcome {
    Triggered { exit_code: i32 },
    Exhausted,
}

fn command_preview(command: &[String]) -> String {
    let preview = command.join(" ");
    if preview.len() > 240 {
        format!("{}...", &preview[..240])
    } else {
        preview
    }
}

fn proc_exists(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

fn proc_status_snapshot(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .map(|status| {
            status
                .lines()
                .filter(|line| {
                    line.starts_with("Name")
                        || line.starts_with("Pid")
                        || line.starts_with("PPid")
                        || line.starts_with("TracerPid")
                        || line.starts_with("State")
                        || line.starts_with("SigQ")
                        || line.starts_with("SigPnd")
                        || line.starts_with("ShdPnd")
                        || line.starts_with("SigBlk")
                        || line.starts_with("SigIgn")
                        || line.starts_with("SigCgt")
                })
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_else(|error| format!("<status_error={error}>"))
}

fn proc_stat_snapshot(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|stat| {
            let fields = stat.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 9 {
                format!(
                    "pid={} comm={} state={} ppid={} pgrp={} session={} tty_nr={} tpgid={} flags={}",
                    fields[0],
                    fields[1],
                    fields[2],
                    fields[3],
                    fields[4],
                    fields[5],
                    fields[6],
                    fields[7],
                    fields[8],
                )
            } else {
                format!("<short_stat={stat}>")
            }
        })
        .unwrap_or_else(|error| format!("<stat_error={error}>"))
}

fn proc_cmdline_snapshot(pid: u32) -> String {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            let joined = raw
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            if joined.is_empty() {
                "<empty>".to_string()
            } else {
                joined
            }
        })
        .unwrap_or_else(|error| format!("<cmdline_error={error}>"))
}

fn proc_wchan_snapshot(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/wchan"))
        .map(|wchan| {
            let trimmed = wchan.trim();
            if trimmed.is_empty() {
                "<empty>".to_string()
            } else {
                trimmed.to_string()
            }
        })
        .unwrap_or_else(|error| format!("<wchan_error={error}>"))
}

fn proc_children_snapshot(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .map(|children| {
            let trimmed = children.trim();
            if trimmed.is_empty() {
                "<none>".to_string()
            } else {
                trimmed.to_string()
            }
        })
        .unwrap_or_else(|error| format!("<children_error={error}>"))
}

fn proc_exe_snapshot(pid: u32) -> String {
    fs::read_link(format!("/proc/{pid}/exe"))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|error| format!("<exe_error={error}>"))
}

fn proc_maps_snapshot(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|maps| {
            let interesting = maps
                .lines()
                .filter(|line| {
                    line.contains("/bin/bash")
                        || line.contains("libproot")
                        || line.contains("ld-musl")
                        || line.contains("linker")
                        || line.contains("[vdso]")
                        || line.contains(" r-xp ")
                })
                .take(12)
                .collect::<Vec<_>>();
            if interesting.is_empty() {
                maps.lines().take(6).collect::<Vec<_>>().join(" || ")
            } else {
                interesting.join(" || ")
            }
        })
        .unwrap_or_else(|error| format!("<maps_error={error}>"))
}

fn describe_wait_semantics(exit_code: Option<i32>, wait_signal: Option<i32>) -> String {
    let inferred_signal = exit_code.and_then(|code| (code > 128).then_some(code - 128));
    let termination_kind = if wait_signal.is_some() {
        "signal"
    } else if exit_code.is_some() {
        "exit_code"
    } else {
        "unknown"
    };
    let signal_consistency = match (wait_signal, inferred_signal) {
        (Some(actual), Some(inferred)) if actual == inferred => "match",
        (Some(_), Some(_)) => "mismatch",
        (Some(_), None) => "signal_only",
        (None, Some(_)) => "exit_only",
        (None, None) => "none",
    };
    format!(
        "wait_semantics=termination_kind={} wait_signal={} inferred_signal={} signal_consistency={}",
        termination_kind,
        wait_signal.map(|signal| signal.to_string()).unwrap_or_else(|| "<none>".to_string()),
        inferred_signal.map(|signal| signal.to_string()).unwrap_or_else(|| "<none>".to_string()),
        signal_consistency,
    )
}

fn summarize_output(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }

    let escaped = String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(|ch| ch.escape_default())
        .collect::<String>();

    if escaped.len() <= 4096 {
        escaped
    } else {
        format!("{}...<truncated>...{}", &escaped[..2048], &escaped[escaped.len() - 1024..])
    }
}

fn should_log_attempt(attempt: u32) -> bool {
    attempt <= 3 || attempt % 25 == 0
}

fn sample_process(pid: u32, rounds: u32, interval_ms: u64) -> Vec<String> {
    let mut lines = Vec::new();
    let started_at = Instant::now();
    let mut last_identity: Option<String> = None;

    for round in 1..=rounds {
        let elapsed_ms = started_at.elapsed().as_millis();
        if !proc_exists(pid) {
            lines.push(format!(
                "[execprobe:sample-missing,round={},elapsed_ms={},pid={}]",
                round, elapsed_ms, pid,
            ));
            break;
        }

        let status_snapshot = proc_status_snapshot(pid);
        let stat_snapshot = proc_stat_snapshot(pid);
        let cmdline_snapshot = proc_cmdline_snapshot(pid);
        let exe_snapshot = proc_exe_snapshot(pid);
        let wchan_snapshot = proc_wchan_snapshot(pid);
        let children_snapshot = proc_children_snapshot(pid);
        let identity = format!(
            "stat=[{}] cmdline=[{}] exe=[{}]",
            stat_snapshot, cmdline_snapshot, exe_snapshot,
        );

        // When the failing window is only a few milliseconds wide, plain per-round /proc
        // dumps are hard to align after the fact. Emit elapsed time on every sample and a
        // dedicated identity-change record whenever exec hands off to a different image, so
        // the next repro can tell exactly which native boundary was crossed last.
        lines.push(format!(
            "[execprobe:sample-round,round={},elapsed_ms={},pid={}]",
            round, elapsed_ms, pid,
        ));
        if round == 1 || last_identity.as_deref() != Some(identity.as_str()) {
            lines.push(format!(
                "[execprobe:sample-identity-change,round={},elapsed_ms={},pid={}] {}",
                round, elapsed_ms, pid, identity,
            ));
            lines.push(format!(
                "[execprobe:sample-maps,round={},elapsed_ms={},pid={}] {}",
                round,
                elapsed_ms,
                pid,
                proc_maps_snapshot(pid),
            ));
            last_identity = Some(identity);
        }

        lines.push(format!(
            "[execprobe:sample-status,round={},elapsed_ms={},pid={}] {}",
            round,
            elapsed_ms,
            pid,
            status_snapshot,
        ));
        lines.push(format!(
            "[execprobe:sample-stat,round={},elapsed_ms={},pid={}] {}",
            round,
            elapsed_ms,
            pid,
            stat_snapshot,
        ));
        lines.push(format!(
            "[execprobe:sample-cmdline,round={},elapsed_ms={},pid={}] {}",
            round,
            elapsed_ms,
            pid,
            cmdline_snapshot,
        ));
        lines.push(format!(
            "[execprobe:sample-exe,round={},elapsed_ms={},pid={}] {}",
            round,
            elapsed_ms,
            pid,
            exe_snapshot,
        ));
        lines.push(format!(
            "[execprobe:sample-wchan,round={},elapsed_ms={},pid={}] {}",
            round,
            elapsed_ms,
            pid,
            wchan_snapshot,
        ));
        lines.push(format!(
            "[execprobe:sample-children,round={},elapsed_ms={},pid={}] {}",
            round,
            elapsed_ms,
            pid,
            children_snapshot,
        ));

        if round < rounds {
            thread::sleep(Duration::from_millis(interval_ms));
        }
    }

    lines
}

fn effective_exit_code(exit_code: Option<i32>, wait_signal: Option<i32>) -> Option<i32> {
    exit_code.or_else(|| wait_signal.map(|signal| 128 + signal))
}

fn build_wrapped_command(
    command: &[String],
    wrap_sig54_probe: bool,
    arm_ms: u64,
    sig54_probe_preserve_blocked_on_exec: bool,
) -> anyhow::Result<Vec<String>> {
    if !wrap_sig54_probe {
        return Ok(command.to_vec());
    }

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut wrapped = vec![current_exe.display().to_string()];
    wrapped.push("sig54-probe".to_string());
    wrapped.push("--signal".to_string());
    wrapped.push("54".to_string());
    wrapped.push("--arm-ms".to_string());
    wrapped.push(arm_ms.to_string());
    if sig54_probe_preserve_blocked_on_exec {
        wrapped.push("--preserve-blocked-on-exec".to_string());
    }
    wrapped.push("--".to_string());
    wrapped.extend(command.iter().cloned());
    Ok(wrapped)
}

pub fn run_exec_probe(
    stop_on_exit_code: i32,
    max_attempts: u32,
    pause_ms: u64,
    sample_rounds: u32,
    sample_interval_ms: u64,
    wrap_sig54_probe: bool,
    sig54_probe_preserve_blocked_on_exec: bool,
    arm_ms: u64,
    command: Vec<String>,
) -> anyhow::Result<ExecProbeOutcome> {
    if stop_on_exit_code <= 0 {
        bail!("stop_on_exit_code must be positive");
    }
    if command.is_empty() {
        bail!("wrapped command is required");
    }
    if sample_rounds == 0 {
        bail!("sample_rounds must be at least 1");
    }

    let pid = std::process::id();
    let parent_pid = unsafe { libc::getppid() };
    eprintln!(
        "[execprobe:start,pid={},ppid={},stop_on_exit_code={},max_attempts={},pause_ms={},sample_rounds={},sample_interval_ms={},wrap_sig54_probe={},sig54_probe_preserve_blocked_on_exec={},arm_ms={},command={}]",
        pid,
        parent_pid,
        stop_on_exit_code,
        max_attempts,
        pause_ms,
        sample_rounds,
        sample_interval_ms,
        if wrap_sig54_probe { 1 } else { 0 },
        if sig54_probe_preserve_blocked_on_exec { 1 } else { 0 },
        arm_ms,
        command_preview(&command),
    );
    eprintln!(
        "[execprobe:self-status,pid={}] {}",
        pid,
        proc_status_snapshot(pid),
    );
    if parent_pid > 0 {
        eprintln!(
            "[execprobe:parent-status,pid={}] {}",
            parent_pid,
            proc_status_snapshot(parent_pid as u32),
        );
    }

    let mut attempt = 0_u32;
    loop {
        if max_attempts != 0 && attempt >= max_attempts {
            eprintln!(
                "[execprobe:exhausted,pid={},attempts={},stop_on_exit_code={}]",
                pid,
                attempt,
                stop_on_exit_code,
            );
            return Ok(ExecProbeOutcome::Exhausted);
        }

        attempt += 1;
        let wrapped_command = build_wrapped_command(
            &command,
            wrap_sig54_probe,
            arm_ms,
            sig54_probe_preserve_blocked_on_exec,
        )?;
        if should_log_attempt(attempt) {
            eprintln!(
                "[execprobe:attempt-begin,index={},command={}]",
                attempt,
                command_preview(&wrapped_command),
            );
        }

        let started_at = Instant::now();
        let mut child = Command::new(&wrapped_command[0])
            .args(&wrapped_command[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn probe command: {}", command_preview(&wrapped_command)))?;
        let child_pid = child.id();
        let monitor = thread::spawn(move || sample_process(child_pid, sample_rounds, sample_interval_ms));
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for child pid={child_pid}"))?;
        let runtime_ms = started_at.elapsed().as_millis();
        let samples = monitor.join().unwrap_or_else(|_| {
            vec![format!(
                "[execprobe:sample-thread-panicked,pid={},index={}]",
                child_pid, attempt,
            )]
        });

        let wait_status = output.status.to_string(); // 仅调试用
        let exit_code = output.status.code(); // 仅调试用
        let wait_signal = output.status.signal(); // 仅调试用
        let status_success = output.status.success(); // 仅调试用
        let raw_wait_status = output.status.into_raw(); // 仅调试用
        let effective_code = effective_exit_code(exit_code, wait_signal);
        let wait_semantics = describe_wait_semantics(exit_code, wait_signal);
        let triggered = effective_code == Some(stop_on_exit_code);
        let should_dump = triggered || should_log_attempt(attempt) || !status_success; // 仅调试用

        if should_dump {
            eprintln!(
            "[execprobe:attempt-end,index={},pid={},runtime_ms={},wait_status={},raw_wait_status={},exit_code={:?},wait_signal={:?},effective_exit_code={:?},triggered={},{}]",
                attempt,
                child_pid,
                runtime_ms,
            wait_status,
            raw_wait_status,
                exit_code,
                wait_signal,
                effective_code,
                if triggered { 1 } else { 0 },
                wait_semantics,
            );
            for line in samples {
                eprintln!("{}", line);
            }
            eprintln!(
                "[execprobe:stdout,index={},pid={}] {}",
                attempt,
                child_pid,
                summarize_output(&output.stdout),
            );
            eprintln!(
                "[execprobe:stderr,index={},pid={}] {}",
                attempt,
                child_pid,
                summarize_output(&output.stderr),
            );
        }

        if triggered {
            eprintln!(
                "[execprobe:trigger,index={},pid={},stop_on_exit_code={}]",
                attempt,
                child_pid,
                stop_on_exit_code,
            );
            eprintln!(
                "[execprobe:self-status-trigger,pid={}] {}",
                pid,
                proc_status_snapshot(pid),
            );
            return Ok(ExecProbeOutcome::Triggered {
                exit_code: effective_code.unwrap_or(stop_on_exit_code),
            });
        }

        if pause_ms > 0 {
            thread::sleep(Duration::from_millis(pause_ms));
        }
    }
}