// Replicate bash 5.3 early startup signal/tty syscalls phase-by-phase to
// localize which operation triggers exit 182 (signal 54 / SIGRTMIN+20) under
// proot. Each phase emits a checkpoint marker; if the probe dies mid-phase the
// exec-probe will capture which phase was the last to emit.
//
// Phases mirror bash's shell_initialize() call chain:
//   1: initialize_traps()  — GETORIGSIG sigaction bounces
//   2: initialize_shell_signals() — sigprocmask read/write + SIGCHLD unblock
//   3: initialize_terminating_signals() — 17× sigaction burst
//   4: initialize_job_signals() — SIGTSTP/SIGTTIN/SIGTTOU → SIG_IGN
//   5: initialize_job_control() — getpgrp/setpgid/tcgetpgrp/tcsetpgrp

use anyhow::{anyhow, bail};
use std::io;

fn proc_signal_snapshot(pid: u32) -> String {
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

fn check_signal_pending(signal: i32) -> anyhow::Result<bool> {
    let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigpending(&mut pending) } != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }
    Ok(unsafe { libc::sigismember(&pending, signal) } == 1)
}

fn read_current_mask() -> anyhow::Result<libc::sigset_t> {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) } != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }
    Ok(mask)
}

fn signal_in_mask(mask: &libc::sigset_t, signal: i32) -> bool {
    unsafe { libc::sigismember(mask, signal) == 1 }
}

fn log_checkpoint(pid: u32, label: &str, signal: i32) {
    let pending = check_signal_pending(signal)
        .map(|v| if v { 1 } else { 0 })
        .unwrap_or(-1);
    let mask = read_current_mask();
    let blocked = mask
        .as_ref()
        .map(|m| if signal_in_mask(m, signal) { 1 } else { 0 })
        .unwrap_or(-1);
    eprintln!(
        "[replay:{},pid={},sig{}_pending={},sig{}_blocked={}]",
        label, pid, signal, pending, signal, blocked,
    );
    eprintln!(
        "[replay:{}-status,pid={}] {}",
        label,
        pid,
        proc_signal_snapshot(pid),
    );
}

/// Phase 1: Replicate bash initialize_traps() GETORIGSIG macro.
/// For each signal: sigaction(sig, SIG_DFL, &old) then sigaction(sig, old, NULL).
/// Creates a brief window where the signal is at SIG_DFL disposition.
fn phase_getorigsig(pid: u32) -> anyhow::Result<()> {
    let signals = [
        libc::SIGCHLD,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
    ];

    for &sig in &signals {
        let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut dfl_action: libc::sigaction = unsafe { std::mem::zeroed() };
        dfl_action.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut dfl_action.sa_mask) };

        // sigaction(sig, SIG_DFL, &old) — temporary SIG_DFL window
        if unsafe { libc::sigaction(sig, &dfl_action, &mut old_action) } != 0 {
            let err = io::Error::last_os_error();
            eprintln!(
                "[replay:getorigsig-err,pid={},sig={},step=set-dfl,err={}]",
                pid, sig, err,
            );
            continue;
        }

        // sigaction(sig, old, NULL) — restore original disposition
        if unsafe { libc::sigaction(sig, &old_action, std::ptr::null_mut()) } != 0 {
            let err = io::Error::last_os_error();
            eprintln!(
                "[replay:getorigsig-err,pid={},sig={},step=restore,err={}]",
                pid, sig, err,
            );
        }
    }

    Ok(())
}

/// Phase 2: Replicate bash initialize_shell_signals() sigprocmask manipulation.
/// Read current mask → remove SIGCHLD → SIG_SETMASK with modified mask.
/// This is the #1 suspected trigger: the SIG_SETMASK call may confuse proot's
/// internal signal tracking, potentially unblocking an RT signal that proot
/// had been suppressing at the ptrace level.
fn phase_sigprocmask_pulse(pid: u32, watched_signal: i32) -> anyhow::Result<()> {
    let mut current_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut current_mask) } != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }

    let sigchld_blocked = signal_in_mask(&current_mask, libc::SIGCHLD);
    let watched_blocked = signal_in_mask(&current_mask, watched_signal);
    eprintln!(
        "[replay:sigprocmask-read,pid={},SIGCHLD_blocked={},sig{}_blocked={}]",
        pid,
        if sigchld_blocked { 1 } else { 0 },
        watched_signal,
        if watched_blocked { 1 } else { 0 },
    );

    // Replicate bash's exact operation: remove SIGCHLD, re-set full mask
    let mut new_mask = current_mask;
    unsafe {
        libc::sigdelset(&mut new_mask, libc::SIGCHLD);
    }

    eprintln!("[replay:sigprocmask-setmask-begin,pid={}]", pid);
    if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &new_mask, std::ptr::null_mut()) } != 0 {
        return Err(anyhow!(io::Error::last_os_error()));
    }
    eprintln!("[replay:sigprocmask-setmask-done,pid={}]", pid);

    Ok(())
}

/// Phase 3: Replicate bash initialize_terminating_signals() — rapid sigaction burst.
/// Installs a dummy handler for 17 terminating signals in a tight loop.
/// Each sigaction() is intercepted by proot via ptrace (syscall-enter + syscall-exit),
/// creating ~34 ptrace stop-resume cycles in quick succession. Suspected: proot's
/// signal delivery logic may drop an internal RT signal during this burst.
fn phase_sigaction_storm(pid: u32) -> anyhow::Result<()> {
    let terminating_signals = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGILL,
        libc::SIGTRAP,
        libc::SIGIOT,
        libc::SIGFPE,
        libc::SIGBUS,
        libc::SIGSEGV,
        libc::SIGSYS,
        libc::SIGPIPE,
        libc::SIGALRM,
        libc::SIGTERM,
        libc::SIGXCPU,
        libc::SIGXFSZ,
        libc::SIGVTALRM,
        libc::SIGUSR1,
        libc::SIGUSR2,
    ];

    // Bash builds a combined mask of all terminating signals for the sa_mask field
    let mut storm_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut storm_mask) };
    for &sig in &terminating_signals {
        unsafe { libc::sigaddset(&mut storm_mask, sig) };
    }

    extern "C" fn dummy_handler(_sig: i32) {}

    for &sig in &terminating_signals {
        let mut new_action: libc::sigaction = unsafe { std::mem::zeroed() };
        new_action.sa_sigaction = dummy_handler as usize;
        new_action.sa_mask = storm_mask;
        new_action.sa_flags = 0;

        let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };

        if unsafe { libc::sigaction(sig, &new_action, &mut old_action) } != 0 {
            let err = io::Error::last_os_error();
            eprintln!("[replay:storm-err,pid={},sig={},err={}]", pid, sig, err);
            continue;
        }

        // Bash restores SIG_IGN for non-interactive shells (preserves inherited ignores)
        if old_action.sa_sigaction == libc::SIG_IGN {
            unsafe { libc::sigaction(sig, &old_action, std::ptr::null_mut()) };
        }
    }

    Ok(())
}

/// Phase 4: Replicate bash initialize_job_signals() — set job control signals to SIG_IGN.
fn phase_job_signals(pid: u32) -> anyhow::Result<()> {
    let job_signals = [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

    for &sig in &job_signals {
        let mut ign_action: libc::sigaction = unsafe { std::mem::zeroed() };
        ign_action.sa_sigaction = libc::SIG_IGN;
        unsafe { libc::sigemptyset(&mut ign_action.sa_mask) };

        if unsafe { libc::sigaction(sig, &ign_action, std::ptr::null_mut()) } != 0 {
            let err = io::Error::last_os_error();
            eprintln!("[replay:jobsig-err,pid={},sig={},err={}]", pid, sig, err);
        }
    }

    Ok(())
}

/// Phase 5: Replicate bash initialize_job_control() — process group and terminal ops.
/// Bash does: getpgrp → tcgetpgrp → setpgid(0, getpid()) → tcsetpgrp.
/// Under exec-probe (piped stdout/stderr) stderr is not a tty, so terminal
/// ops are skipped — matching what bash would do in the same exec-probe context.
fn phase_job_control(pid: u32) -> anyhow::Result<()> {
    let pgrp = unsafe { libc::getpgrp() };
    let my_pid = unsafe { libc::getpid() };
    eprintln!("[replay:job-control,pid={},pgrp={},my_pid={}]", pid, pgrp, my_pid);

    // Check stderr for tty (bash uses fileno(stderr) as shell_tty)
    let stderr_fd = 2;
    let is_tty = unsafe { libc::isatty(stderr_fd) == 1 };
    eprintln!(
        "[replay:job-control,pid={},stderr_isatty={}]",
        pid,
        if is_tty { 1 } else { 0 },
    );

    if is_tty {
        let terminal_pgrp = unsafe { libc::tcgetpgrp(stderr_fd) };
        eprintln!(
            "[replay:job-control,pid={},terminal_pgrp={}]",
            pid, terminal_pgrp,
        );

        let setpgid_rc = unsafe { libc::setpgid(0, my_pid) };
        if setpgid_rc != 0 {
            let err = io::Error::last_os_error();
            eprintln!("[replay:job-control,pid={},setpgid-err={}]", pid, err);
        } else {
            eprintln!("[replay:job-control,pid={},setpgid=ok]", pid);
        }

        let tcsetpgrp_rc = unsafe { libc::tcsetpgrp(stderr_fd, my_pid) };
        if tcsetpgrp_rc != 0 {
            let err = io::Error::last_os_error();
            eprintln!("[replay:job-control,pid={},tcsetpgrp-err={}]", pid, err);
        } else {
            eprintln!("[replay:job-control,pid={},tcsetpgrp=ok]", pid);
        }
    }

    Ok(())
}

pub fn run_startup_replay_probe(signal: i32) -> anyhow::Result<()> {
    if signal <= 0 {
        bail!("signal must be positive");
    }

    let pid = std::process::id();
    let ppid = unsafe { libc::getppid() };

    eprintln!(
        "[replay:start,pid={},ppid={},watched_signal={}]",
        pid, ppid, signal,
    );
    log_checkpoint(pid, "entry", signal);

    // Phase 1: GETORIGSIG — sigaction bounces (bash initialize_traps)
    eprintln!("[replay:phase1-begin,pid={}]", pid);
    phase_getorigsig(pid)?;
    log_checkpoint(pid, "phase1-done", signal);

    // Phase 2: sigprocmask pulse (bash initialize_shell_signals mask manipulation)
    // #1 suspect: SIG_SETMASK may confuse proot's internal signal suppression
    eprintln!("[replay:phase2-begin,pid={}]", pid);
    phase_sigprocmask_pulse(pid, signal)?;
    log_checkpoint(pid, "phase2-done", signal);

    // Phase 3: sigaction storm (bash initialize_terminating_signals, 17× burst)
    // #2 suspect: rapid ptrace stop-resume cycles may leak an RT signal
    eprintln!("[replay:phase3-begin,pid={}]", pid);
    phase_sigaction_storm(pid)?;
    log_checkpoint(pid, "phase3-done", signal);

    // Phase 4: job signal setup (bash initialize_job_signals)
    eprintln!("[replay:phase4-begin,pid={}]", pid);
    phase_job_signals(pid)?;
    log_checkpoint(pid, "phase4-done", signal);

    // Phase 5: job control init (bash initialize_job_control)
    // #4 suspect: process group + terminal control ops under proot PID remapping
    eprintln!("[replay:phase5-begin,pid={}]", pid);
    phase_job_control(pid)?;
    log_checkpoint(pid, "phase5-done", signal);

    eprintln!("[replay:finish,pid={}]", pid);
    println!("[replay:ok,pid={},ppid={}]", pid, ppid);
    Ok(())
}
