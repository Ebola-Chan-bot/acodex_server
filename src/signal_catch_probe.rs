use anyhow::{anyhow, bail};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static HANDLER_HIT: AtomicBool = AtomicBool::new(false);
static HANDLER_SIGNO: AtomicI32 = AtomicI32::new(0);
static HANDLER_CODE: AtomicI32 = AtomicI32::new(0);
static HANDLER_ERRNO: AtomicI32 = AtomicI32::new(0);
static HANDLER_SENDER_PID: AtomicI32 = AtomicI32::new(0);
static HANDLER_SENDER_UID: AtomicU32 = AtomicU32::new(0);

fn proc_signal_snapshot(pid: libc::pid_t) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
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

fn pending_signal(signal: i32) -> anyhow::Result<bool> {
    let mut pending_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let pending_rc = unsafe { libc::sigpending(&mut pending_set) };
    if pending_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    Ok(unsafe { libc::sigismember(&pending_set, signal) == 1 })
}

extern "C" fn signal_handler(signo: i32, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
    HANDLER_SIGNO.store(signo, Ordering::SeqCst);
    if !info.is_null() {
        let siginfo = unsafe { &*info };
        HANDLER_CODE.store(siginfo.si_code, Ordering::SeqCst);
        HANDLER_ERRNO.store(siginfo.si_errno, Ordering::SeqCst);
        HANDLER_SENDER_PID.store(unsafe { siginfo.si_pid() }, Ordering::SeqCst);
        HANDLER_SENDER_UID.store(unsafe { siginfo.si_uid() }, Ordering::SeqCst);
    }
    HANDLER_HIT.store(true, Ordering::SeqCst);
}

fn install_signal_handler(signal: i32) -> anyhow::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_flags = libc::SA_SIGINFO;
    action.sa_sigaction = signal_handler as usize;

    let empty_mask_rc = unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if empty_mask_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    let sigaction_rc = unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
    if sigaction_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    Ok(())
}

pub fn run_signal_catch_probe(signal: i32, wait_ms: u64) -> anyhow::Result<()> {
    if signal <= 0 {
        bail!("signal must be positive");
    }

    HANDLER_HIT.store(false, Ordering::SeqCst);
    HANDLER_SIGNO.store(0, Ordering::SeqCst);
    HANDLER_CODE.store(0, Ordering::SeqCst);
    HANDLER_ERRNO.store(0, Ordering::SeqCst);
    HANDLER_SENDER_PID.store(0, Ordering::SeqCst);
    HANDLER_SENDER_UID.store(0, Ordering::SeqCst);

    let pid = std::process::id();
    let parent_pid = unsafe { libc::getppid() };
    eprintln!(
        "[sigcatch:start,pid={},ppid={},signal={},wait_ms={}]",
        pid,
        parent_pid,
        signal,
        wait_ms,
    );
    eprintln!(
        "[sigcatch:status-entry,pid={}] {}",
        pid,
        proc_signal_snapshot(pid as libc::pid_t),
    );

    let mut signal_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut signal_set);
        libc::sigaddset(&mut signal_set, signal);
    }

    let mut old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // 仅调试用: 这个 target 的目标就是验证“如果在 exec 前把 54 保持为 blocked，
    // 刚进入新进程就立刻装 handler 并放行 54，问题还会不会继续表现为 182”。这样
    // 可以把“bash 特有启动窗口”与“任何新进程都会在 handoff 后立刻收到 54”分开。 
    let block_rc = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &signal_set, &mut old_mask) };
    if block_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    let blocked_on_entry = unsafe { libc::sigismember(&old_mask, signal) == 1 };
    eprintln!(
        "[sigcatch:mask-entry,pid={},signal={},blocked_on_entry={}]",
        pid,
        signal,
        if blocked_on_entry { 1 } else { 0 },
    );
    eprintln!(
        "[sigcatch:status-blocked,pid={}] {}",
        pid,
        proc_signal_snapshot(pid as libc::pid_t),
    );
    eprintln!(
        "[sigcatch:pending-before-handler,pid={},signal={},pending={}]",
        pid,
        signal,
        if pending_signal(signal)? { 1 } else { 0 },
    );

    install_signal_handler(signal)?;
    eprintln!("[sigcatch:handler-installed,pid={},signal={}]", pid, signal);

    let mut delivery_mask = old_mask;
    unsafe {
        libc::sigdelset(&mut delivery_mask, signal);
    }
    let unblock_rc = unsafe { libc::sigprocmask(libc::SIG_SETMASK, &delivery_mask, std::ptr::null_mut()) };
    if unblock_rc != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    eprintln!(
        "[sigcatch:status-unblocked,pid={}] {}",
        pid,
        proc_signal_snapshot(pid as libc::pid_t),
    );

    let started_at = Instant::now();
    let wait_window = Duration::from_millis(wait_ms);
    while started_at.elapsed() < wait_window {
        if HANDLER_HIT.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let elapsed_ms = started_at.elapsed().as_millis();
    let pending_after = pending_signal(signal)?;
    if HANDLER_HIT.load(Ordering::SeqCst) {
        eprintln!(
            "[sigcatch:handler-hit,pid={},elapsed_ms={},signo={},code={},errno={},sender_pid={},sender_uid={},pending_after={}]",
            pid,
            elapsed_ms,
            HANDLER_SIGNO.load(Ordering::SeqCst),
            HANDLER_CODE.load(Ordering::SeqCst),
            HANDLER_ERRNO.load(Ordering::SeqCst),
            HANDLER_SENDER_PID.load(Ordering::SeqCst),
            HANDLER_SENDER_UID.load(Ordering::SeqCst),
            if pending_after { 1 } else { 0 },
        );
    } else {
        eprintln!(
            "[sigcatch:handler-timeout,pid={},elapsed_ms={},pending_after={}]",
            pid,
            elapsed_ms,
            if pending_after { 1 } else { 0 },
        );
    }

    eprintln!(
        "[sigcatch:status-finish,pid={}] {}",
        pid,
        proc_signal_snapshot(pid as libc::pid_t),
    );
    println!(
        "[sigcatch:stdout-marker,pid={},caught={},blocked_on_entry={}]",
        pid,
        if HANDLER_HIT.load(Ordering::SeqCst) { 1 } else { 0 },
        if blocked_on_entry { 1 } else { 0 },
    );
    Ok(())
}