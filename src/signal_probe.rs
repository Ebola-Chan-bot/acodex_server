use anyhow::{anyhow, bail, Context};
use std::ffi::CString;
use std::io;
use std::time::{Duration, Instant};

fn command_preview(command: &[String]) -> String {
    let preview = command.join(" ");
    if preview.len() > 200 {
        format!("{}...", &preview[..200])
    } else {
        preview
    }
}

fn proc_signal_snapshot(pid: libc::pid_t) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map(|status| {
            status
                .lines()
                .filter(|line| {
                    line.starts_with("Name")
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

fn duration_to_timespec(duration: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: duration.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: duration.subsec_nanos().into(),
    }
}

#[derive(Debug)]
struct CapturedSignalInfo {
    signo: i32,
    code: i32,
    errno: i32,
    sender_pid: libc::pid_t,
    sender_uid: libc::uid_t,
}

fn wait_for_signal(
    signal: i32,
    signal_set: &libc::sigset_t,
    arm_window: Duration,
) -> anyhow::Result<Option<CapturedSignalInfo>> {
    let started_at = Instant::now();

    loop {
        let elapsed = started_at.elapsed();
        if elapsed >= arm_window {
            return Ok(None);
        }

        let remaining = arm_window
            .checked_sub(elapsed)
            .unwrap_or_else(|| Duration::from_millis(0));
        let timeout = duration_to_timespec(remaining);
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::sigtimedwait(signal_set, &mut siginfo, &timeout) };
        if rc == signal {
            return Ok(Some(CapturedSignalInfo {
                signo: siginfo.si_signo,
                code: siginfo.si_code,
                errno: siginfo.si_errno,
                sender_pid: unsafe { siginfo.si_pid() },
                sender_uid: unsafe { siginfo.si_uid() },
            }));
        }

        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EAGAIN) => return Ok(None),
            Some(libc::EINTR) => continue,
            _ => return Err(anyhow!(error)),
        }
    }
}

fn exec_command(
    command: &[String],
    old_mask: &libc::sigset_t,
    signal: i32,
    preserve_blocked_on_exec: bool,
) -> anyhow::Result<()> {
    let pid = std::process::id();
    let preview = command_preview(command);
    let cstrings = command
        .iter()
        .map(|arg| CString::new(arg.as_str()).with_context(|| format!("command contains NUL byte: {arg:?}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut argv = cstrings.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv.push(std::ptr::null());

    let mut exec_mask = *old_mask;
    if preserve_blocked_on_exec {
        unsafe {
            libc::sigaddset(&mut exec_mask, signal);
        }
    }

    // Restore the exact mask inherited from axs before exec. The passive line already
    // observes bash under that inherited mask, so the active probe must hand off the
    // same signal state after its arm window instead of introducing a second variable.
    // 仅调试用: signal catcher target 需要把 54 保持为 blocked 跨过 exec，才能在
    // 新进程一进入用户态时先装 handler 再放行 54。默认仍保持旧行为，避免污染原始
    // bash 路径的对照样本。 
    let setmask_rc = unsafe { libc::sigprocmask(libc::SIG_SETMASK, &exec_mask, std::ptr::null_mut()) };
    if setmask_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    // 仅调试用: 当前最大歧义是“timeout 后根本没进入 exec”与“已经 handoff 给
    // 被测命令，182 发生在 handoff 之后”混在一起。这里在 execvp 前打出唯一标记，
    // 以后只要日志里出现它且随后没有 sigprobe:error，就能确认 182 不属于 probe
    // 自己的 pre-exec 阶段。
    eprintln!("[sigprobe:exec-handoff,pid={},command={}]", pid, preview);

    unsafe {
        libc::execvp(cstrings[0].as_ptr(), argv.as_ptr());
    }

    let error = io::Error::last_os_error();
    eprintln!("[sigprobe:exec-error,pid={},command={},error={}]", pid, preview, error);
    Err(anyhow!(error))
}

pub fn run_signal_probe(
    signal: i32,
    arm_ms: u64,
    preserve_blocked_on_exec: bool,
    command: Vec<String>,
) -> anyhow::Result<()> {
    if signal <= 0 {
        bail!("signal must be positive");
    }
    if command.is_empty() {
        bail!("wrapped command is required");
    }

    let pid = std::process::id();
    let parent_pid = unsafe { libc::getppid() };
    let command_preview = command_preview(&command);
    let arm_window = Duration::from_millis(arm_ms);

    eprintln!(
        "[sigprobe:start,pid={},ppid={},signal={},arm_ms={},command={}]",
        pid,
        parent_pid,
        signal,
        arm_ms,
        command_preview,
    );
    eprintln!(
        "[sigprobe:status-before,pid={}] {}",
        pid,
        proc_signal_snapshot(pid as libc::pid_t),
    );

    let mut signal_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut signal_set);
        libc::sigaddset(&mut signal_set, signal);
    }

    let mut old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let block_rc = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &signal_set, &mut old_mask) };
    if block_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    eprintln!(
        "[sigprobe:status-armed,pid={}] {}",
        pid,
        proc_signal_snapshot(pid as libc::pid_t),
    );

    let started_at = Instant::now();
    let captured = wait_for_signal(signal, &signal_set, arm_window)?;
    match captured {
        Some(info) => {
            eprintln!(
                "[sigprobe:caught,pid={},elapsed_ms={},signo={},code={},errno={},sender_pid={},sender_uid={}]",
                pid,
                started_at.elapsed().as_millis(),
                info.signo,
                info.code,
                info.errno,
                info.sender_pid,
                info.sender_uid,
            );
            eprintln!(
                "[sigprobe:status-caught,pid={}] {}",
                pid,
                proc_signal_snapshot(pid as libc::pid_t),
            );

            // Re-deliver the same signal with the default action after logging the
            // original sender fields. Without this replay, the active probe would
            // turn a fatal signal into a normal exit and invalidate comparisons with
            // the passive wait-status evidence collected by axs.
            let mut replay_mask = old_mask;
            unsafe {
                libc::sigdelset(&mut replay_mask, signal);
            }
            let replay_mask_rc =
                unsafe { libc::sigprocmask(libc::SIG_SETMASK, &replay_mask, std::ptr::null_mut()) };
            if replay_mask_rc != 0 {
                return Err(anyhow!(io::Error::last_os_error()));
            }

            eprintln!("[sigprobe:replay-default,pid={},signal={}]", pid, signal);
            unsafe {
                libc::raise(signal);
                libc::_exit(128 + signal);
            }
        }
        None => {
            eprintln!(
                "[sigprobe:timeout,pid={},elapsed_ms={}]",
                pid,
                started_at.elapsed().as_millis(),
            );
            eprintln!(
                "[sigprobe:status-timeout,pid={}] {}",
                pid,
                proc_signal_snapshot(pid as libc::pid_t),
            );
            exec_command(&command, &old_mask, signal, preserve_blocked_on_exec)
        }
    }
}