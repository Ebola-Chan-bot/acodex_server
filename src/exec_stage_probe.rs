use anyhow::{anyhow, bail, Context};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io;

fn command_preview(command: &[String]) -> String {
    let preview = command.join(" ");
    if preview.len() > 240 {
        format!("{}...", &preview[..240])
    } else {
        preview
    }
}

fn proc_status_snapshot(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .map(|status| {
            status
                .lines()
                .filter(|line| {
                    line.starts_with("Name")
                        || line.starts_with("State")
                        || line.starts_with("Pid")
                        || line.starts_with("PPid")
                        || line.starts_with("TracerPid")
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

fn env_subset_snapshot() -> String {
    [
        "PATH",
        "HOME",
        "TERM",
        "LD_LIBRARY_PATH",
        "PROOT",
        "PROOT_LOADER",
        "PROOT_LOADER32",
        "PROOT_TMP_DIR",
    ]
    .iter()
    .filter_map(|key| {
        env::var_os(key).map(|value| format!("{}={}", key, value.to_string_lossy()))
    })
    .collect::<Vec<_>>()
    .join(" | ")
}

fn exec_command(command: &[String]) -> anyhow::Result<()> {
    let cstrings = command
        .iter()
        .map(|arg| CString::new(arg.as_str()).with_context(|| format!("command contains NUL byte: {arg:?}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut argv = cstrings.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv.push(std::ptr::null());

    unsafe {
        libc::execvp(cstrings[0].as_ptr(), argv.as_ptr());
    }

    Err(anyhow!(io::Error::last_os_error()))
}

pub fn run_exec_stage_probe(stage_label: &str, command: Vec<String>) -> anyhow::Result<()> {
    if command.is_empty() {
        bail!("wrapped command is required");
    }

    let pid = std::process::id();
    let parent_pid = unsafe { libc::getppid() };
    let preview = command_preview(&command);
    let cwd = env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|error| format!("<cwd_error={error}>"));

    // This stage wrapper exists solely to split the old opaque handoff window into
    // two native milestones: "sigprobe -> stage wrapper" and "stage wrapper -> bash".
    // If the next repro still dies before bash markers, these logs tell us whether the
    // failure is already in the second native exec boundary or only after bash starts.
    eprintln!(
        "[stageprobe:start,pid={},ppid={},label={},cwd={},command={}]",
        pid,
        parent_pid,
        stage_label,
        cwd,
        preview,
    );
    eprintln!(
        "[stageprobe:status,pid={},label={}] {}",
        pid,
        stage_label,
        proc_status_snapshot(pid),
    );
    eprintln!(
        "[stageprobe:stat,pid={},label={}] {}",
        pid,
        stage_label,
        proc_stat_snapshot(pid),
    );
    eprintln!(
        "[stageprobe:cmdline,pid={},label={}] {}",
        pid,
        stage_label,
        proc_cmdline_snapshot(pid),
    );
    eprintln!(
        "[stageprobe:exe,pid={},label={}] {}",
        pid,
        stage_label,
        proc_exe_snapshot(pid),
    );
    eprintln!(
        "[stageprobe:maps,pid={},label={}] {}",
        pid,
        stage_label,
        proc_maps_snapshot(pid),
    );
    eprintln!(
        "[stageprobe:env,pid={},label={}] {}",
        pid,
        stage_label,
        env_subset_snapshot(),
    );
    eprintln!(
        "[stageprobe:exec-begin,pid={},label={},command={}]",
        pid,
        stage_label,
        preview,
    );

    if let Err(error) = exec_command(&command) {
        eprintln!(
            "[stageprobe:exec-error,pid={},label={},command={},error={}]",
            pid,
            stage_label,
            preview,
            error,
        );
        return Err(error);
    }

    Ok(())
}