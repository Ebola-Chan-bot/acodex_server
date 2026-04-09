//! Fallback PTY implementation using the Linux TIOCGPTPEER ioctl.
//!
//! When the standard `openpty()` path fails — typically because SELinux blocks
//! `open("/dev/pts/N")` — this module creates the master/slave pair via
//! `/dev/ptmx` + `TIOCGPTPEER`, then spawns the child with
//! `std::process::Command`.

use anyhow::{bail, Error};
use portable_pty::{Child, MasterPty, PtySize};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::thread; // 仅调试用
use std::time::Duration; // 仅调试用

fn describe_pts_fd(fd: RawFd) -> String {
    let mut buffer = [0u8; 128]; // 仅调试用
    let rc = unsafe { libc::ptsname_r(fd, buffer.as_mut_ptr() as *mut _, buffer.len()) }; // 仅调试用
    if rc != 0 { // 仅调试用
        return format!("ptsname_r_error={:?}", io::Error::from_raw_os_error(rc)); // 仅调试用
    } // 仅调试用
    let nul = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len()); // 仅调试用
    format!( // 仅调试用
        "pts_name={}", // 仅调试用
        String::from_utf8_lossy(&buffer[..nul]) // 仅调试用
    ) // 仅调试用
}

/// `TIOCGPTPEER` — obtain the slave fd directly from the master fd.
/// Defined in `<linux/tty.h>` as `_IO('T', 0x41)` = `0x5441`.
/// Architecture-independent on Linux.
const TIOCGPTPEER: libc::c_ulong = 0x5441;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 0x4;

// ---------------------------------------------------------------------------
// OwnedFd — thin RAII wrapper around a raw file descriptor
// ---------------------------------------------------------------------------

struct OwnedFd(RawFd);

impl OwnedFd {
    fn try_clone(&self) -> io::Result<Self> {
        let fd = unsafe { libc::dup(self.0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Set CLOEXEC so cloned fds don't leak into spawned child processes.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        Ok(OwnedFd(fd))
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl Read for OwnedFd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EIO) => return Ok(0), // slave closed → EOF
                    _ => return Err(err),
                }
            }
            return Ok(n as usize);
        }
    }
}

fn summarize_proc_cmdline(bytes: &[u8]) -> String { // 仅调试用
    let parts = bytes // 仅调试用
        .split(|byte| *byte == 0) // 仅调试用
        .filter(|part| !part.is_empty()) // 仅调试用
        .map(|part| String::from_utf8_lossy(part).into_owned()) // 仅调试用
        .collect::<Vec<_>>(); // 仅调试用
    if parts.is_empty() { // 仅调试用
        return String::from("<empty>"); // 仅调试用
    } // 仅调试用
    parts.join(" ") // 仅调试用
} // 仅调试用

fn collect_child_proc_snapshot(pid: u32) -> String { // 仅调试用
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")) // 仅调试用
        .map(|status| { // 仅调试用
            status // 仅调试用
                .lines() // 仅调试用
                .filter(|line| { // 仅调试用
                    line.starts_with("Name") // 仅调试用
                        || line.starts_with("State") // 仅调试用
                        || line.starts_with("Tgid") // 仅调试用
                        || line.starts_with("Pid") // 仅调试用
                        || line.starts_with("PPid") // 仅调试用
                        || line.starts_with("TracerPid") // 仅调试用
                        || line.starts_with("SigQ") // 仅调试用
                        || line.starts_with("SigPnd") // 仅调试用
                        || line.starts_with("ShdPnd") // 仅调试用
                        || line.starts_with("SigBlk") // 仅调试用
                        || line.starts_with("SigIgn") // 仅调试用
                        || line.starts_with("SigCgt") // 仅调试用
                }) // 仅调试用
                .collect::<Vec<_>>() // 仅调试用
                .join(" | ") // 仅调试用
        }) // 仅调试用
        .unwrap_or_else(|error| format!("<status_error={error}>")); // 仅调试用
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")) // 仅调试用
        .map(|bytes| summarize_proc_cmdline(&bytes)) // 仅调试用
        .unwrap_or_else(|error| format!("<cmdline_error={error}>")); // 仅调试用
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")) // 仅调试用
        .map(|path| path.display().to_string()) // 仅调试用
        .unwrap_or_else(|error| format!("<exe_error={error}>")); // 仅调试用
    format!("exe={} cmdline={} [{}]", exe, cmdline, status) // 仅调试用
} // 仅调试用

fn spawn_child_status_probe(pid: u32) { // 仅调试用
    tracing::warn!( // 仅调试用
        "PTY child early-status armed pid={} rounds=6 interval_ms=2 revision=20260327b", // 仅调试用
        pid, // 仅调试用
    ); // 仅调试用
    thread::spawn(move || { // 仅调试用
        for round in 1..=6 { // 仅调试用
            let status_path = format!("/proc/{pid}/status"); // 仅调试用
            match std::fs::read_to_string(&status_path) { // 仅调试用
                Ok(status) => { // 仅调试用
                    let snapshot = status // 仅调试用
                        .lines() // 仅调试用
                        .filter(|line| { // 仅调试用
                            line.starts_with("Name") // 仅调试用
                                || line.starts_with("State") // 仅调试用
                                || line.starts_with("Tgid") // 仅调试用
                                || line.starts_with("Pid") // 仅调试用
                                || line.starts_with("PPid") // 仅调试用
                                || line.starts_with("TracerPid") // 仅调试用
                                || line.starts_with("SigQ") // 仅调试用
                                || line.starts_with("SigPnd") // 仅调试用
                                || line.starts_with("ShdPnd") // 仅调试用
                                || line.starts_with("SigBlk") // 仅调试用
                                || line.starts_with("SigIgn") // 仅调试用
                                || line.starts_with("SigCgt") // 仅调试用
                        }) // 仅调试用
                        .collect::<Vec<_>>() // 仅调试用
                        .join(" | "); // 仅调试用
                    tracing::warn!( // 仅调试用
                        "PTY child early-status pid={} round={} {}", // 仅调试用
                        pid, // 仅调试用
                        round, // 仅调试用
                        collect_child_proc_snapshot(pid), // 仅调试用
                    ); // 仅调试用
                } // 仅调试用
                Err(error) if error.kind() == io::ErrorKind::NotFound => { // 仅调试用
                    tracing::warn!( // 仅调试用
                        "PTY child early-status pid={} round={} proc-missing", // 仅调试用
                        pid, // 仅调试用
                        round, // 仅调试用
                    ); // 仅调试用
                    break; // 仅调试用
                } // 仅调试用
                Err(error) => { // 仅调试用
                    tracing::warn!( // 仅调试用
                        "PTY child early-status pid={} round={} read_error={}", // 仅调试用
                        pid, // 仅调试用
                        round, // 仅调试用
                        error, // 仅调试用
                    ); // 仅调试用
                    break; // 仅调试用
                } // 仅调试用
            } // 仅调试用
            thread::sleep(Duration::from_millis(2)); // 仅调试用
        } // 仅调试用
    }); // 仅调试用
} // 仅调试用

impl Write for OwnedFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let n = unsafe { libc::write(self.0, buf.as_ptr() as *const _, buf.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    _ => return Err(err),
                }
            }
            return Ok(n as usize);
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FallbackMasterPty — implements portable_pty::MasterPty
// ---------------------------------------------------------------------------

struct FallbackMasterPty {
    fd: OwnedFd,
    took_writer: RefCell<bool>,
}

impl std::fmt::Debug for FallbackMasterPty {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("FallbackMasterPty")
            .field("fd", &self.fd.0)
            .finish()
    }
}

impl MasterPty for FallbackMasterPty {
    fn resize(&self, size: PtySize) -> Result<(), Error> {
        let ws = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCSWINSZ as _, &ws as *const _) } != 0
        {
            bail!("ioctl(TIOCSWINSZ) failed: {:?}", io::Error::last_os_error());
        }
        Ok(())
    }

    fn get_size(&self) -> Result<PtySize, Error> {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::TIOCGWINSZ as _,
                &mut ws as *mut _,
            )
        } != 0
        {
            bail!("ioctl(TIOCGWINSZ) failed: {:?}", io::Error::last_os_error());
        }
        Ok(PtySize {
            rows: ws.ws_row,
            cols: ws.ws_col,
            pixel_width: ws.ws_xpixel,
            pixel_height: ws.ws_ypixel,
        })
    }

    fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>, Error> {
        Ok(Box::new(self.fd.try_clone()?))
    }

    fn take_writer(&self) -> Result<Box<dyn Write + Send>, Error> {
        if *self.took_writer.borrow() {
            bail!("cannot take writer more than once");
        }
        *self.took_writer.borrow_mut() = true;
        Ok(Box::new(FallbackMasterWriter {
            fd: self.fd.try_clone()?,
        }))
    }

    fn process_group_leader(&self) -> Option<libc::pid_t> {
        match unsafe { libc::tcgetpgrp(self.fd.as_raw_fd()) } {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }

    fn as_raw_fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }

    fn tty_name(&self) -> Option<std::path::PathBuf> {
        None
    }
}

// ---------------------------------------------------------------------------
// FallbackMasterWriter — sends EOT on drop, matching portable-pty behaviour
// ---------------------------------------------------------------------------

struct FallbackMasterWriter {
    fd: OwnedFd,
}

impl Write for FallbackMasterWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.fd.flush()
    }
}

impl Drop for FallbackMasterWriter {
    fn drop(&mut self) {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(self.fd.as_raw_fd(), &mut t) == 0 {
                let eot = t.c_cc[libc::VEOF];
                if eot != 0 {
                    let _ = self.fd.write_all(&[b'\n', eot]);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: prevent fd leaks without breaking Rust's exec-error pipe
// ---------------------------------------------------------------------------

/// Mark all fds above stderr as close-on-exec in the child process.
///
/// This preserves Rust's internal exec-error reporting pipe until `execve`,
/// avoiding the stdlib abort seen when the pipe is closed too early, while
/// still preventing descriptor leaks into the spawned program.
unsafe fn cloexec_fds_above_stderr() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let res = libc::syscall(
            libc::SYS_close_range,
            3u64,
            u32::MAX as u64,
            CLOSE_RANGE_CLOEXEC as u64,
        );
        if res == 0 {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Open a PTY using TIOCGPTPEER and spawn a command.
///
/// Fallback for when `portable_pty::native_pty_system().openpty()` fails
/// (e.g. SELinux blocks `open("/dev/pts/N")`).
pub fn fallback_open_and_spawn(
    size: PtySize,
    program: &str,
    args: &[String],
) -> anyhow::Result<(Box<dyn MasterPty + Send>, Box<dyn Child + Send + Sync>, String)> {
    use std::os::unix::process::CommandExt;

    tracing::info!( // 仅调试用
        "fallback_open_and_spawn start program={} args={:?} rows={} cols={}", // 仅调试用
        program, // 仅调试用
        args, // 仅调试用
        size.rows, // 仅调试用
        size.cols, // 仅调试用
    ); // 仅调试用

    // 1. Open master PTY
    let master_fd = unsafe { libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if master_fd < 0 {
        bail!("open(/dev/ptmx) failed: {:?}", io::Error::last_os_error());
    }
    let master = OwnedFd(master_fd);
    tracing::info!("fallback_open_and_spawn open_ptmx master_fd={}", master.as_raw_fd()); // 仅调试用

    // 2. Grant & unlock
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0 {
        bail!("grantpt failed: {:?}", io::Error::last_os_error());
    }
    tracing::info!("fallback_open_and_spawn grantpt_ok master_fd={}", master.as_raw_fd()); // 仅调试用
    if unsafe { libc::unlockpt(master.as_raw_fd()) } != 0 {
        bail!("unlockpt failed: {:?}", io::Error::last_os_error());
    }
    tracing::info!("fallback_open_and_spawn unlockpt_ok master_fd={}", master.as_raw_fd()); // 仅调试用

    // 3. Obtain slave fd via TIOCGPTPEER (bypasses /dev/pts)
    let slave_fd = unsafe {
        libc::ioctl(
            master.as_raw_fd(),
            TIOCGPTPEER as _,
            libc::O_RDWR | libc::O_NOCTTY,
        )
    };
    if slave_fd < 0 {
        bail!(
            "ioctl(TIOCGPTPEER) failed: {:?}",
            io::Error::last_os_error()
        );
    }
    let fallback_detail = format!( // 仅调试用
        "master_fd={} slave_fd={} {}", // 仅调试用
        master.as_raw_fd(), // 仅调试用
        slave_fd, // 仅调试用
        describe_pts_fd(master.as_raw_fd()), // 仅调试用
    ); // 仅调试用
    tracing::info!( // 仅调试用
        "fallback_open_and_spawn tiocgptpeer_ok {}", // 仅调试用
        fallback_detail, // 仅调试用
    ); // 仅调试用

    // 4. Set window size (non-fatal — the first resize from the client will
    //    correct it anyway, so we only log on failure rather than aborting).
    let ws = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws as *const _) } == -1 {
        tracing::warn!(
            "ioctl(TIOCSWINSZ) failed (non-fatal): {:?}",
            io::Error::last_os_error()
        );
    }

    // 5. Prepare Stdio from slave fd (one dup per stream).
    //    Wrap slave_fd in OwnedFd so it is closed on all paths
    //    (including early ? returns from mk_stdio).
    let (child_stdin, child_stdout, child_stderr) = {
        let slave = OwnedFd(slave_fd);
        let mk_stdio = || -> anyhow::Result<std::process::Stdio> {
            let fd = unsafe { libc::dup(slave.as_raw_fd()) };
            if fd < 0 {
                bail!("dup(slave_fd) failed: {:?}", io::Error::last_os_error());
            }
            Ok(unsafe { std::process::Stdio::from_raw_fd(fd) })
        };
        let stdin = mk_stdio()?;
        let stdout = mk_stdio()?;
        let stderr = mk_stdio()?;
        (stdin, stdout, stderr)
        // `slave` (OwnedFd) is dropped here, closing the original slave_fd.
    };
    tracing::info!("fallback_open_and_spawn dup_stdio_ok {}", fallback_detail); // 仅调试用

    // 6. Spawn command
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    unsafe {
        cmd.stdin(child_stdin)
            .stdout(child_stdout)
            .stderr(child_stderr)
            .pre_exec(|| {
                // Reset signal dispositions
                for signo in &[
                    libc::SIGCHLD,
                    libc::SIGHUP,
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTERM,
                    libc::SIGALRM,
                ] {
                    libc::signal(*signo, libc::SIG_DFL);
                }

                // Signal 54 (SIGRTMIN+20) under proot ptrace kills bash during its
                // first ~7ms. The root cause (loader MAP_FIXED on occupied addresses)
                // has been fixed in proot via fixup_load_addresses. Exit 182 is now
                // treated as an unexpected fatal error by the frontend.
                // Clear all inherited signal blocks so bash starts with a clean mask.
                let mut empty_mask: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut empty_mask);
                libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut());

                // New session
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }

                // Set controlling terminal
                #[allow(clippy::cast_lossless)]
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }

                cloexec_fds_above_stderr();

                // 仅调试用: async-signal-safe diagnostic marker written to PTY.
                // Verifies the slave-to-master link is functional: if this appears
                // in the scrollback after an immediate exit (e.g. exit_code=182),
                // the PTY pair works and the problem is in bash initialization;
                // if scrollback is empty, the PTY link is broken under proot.
                {
                    let is_tty = libc::isatty(0);
                    let pgrp = libc::tcgetpgrp(0);
                    if is_tty == 1 {
                        let _ = libc::write(2, b"[axs:tty=y".as_ptr() as *const _, 10);
                    } else {
                        let _ = libc::write(2, b"[axs:tty=n".as_ptr() as *const _, 10);
                    }
                    if pgrp >= 0 {
                        let _ = libc::write(2, b",pgrp=ok".as_ptr() as *const _, 8);
                    } else {
                        let _ = libc::write(2, b",pgrp=er".as_ptr() as *const _, 8);
                    }

                    // 仅调试用: 测试 tcsetpgrp — bash 启动时会调用此操作做 job control
                    // 初始化。已排除 tcsetpgrp 为崩溃根因：日志显示 setpg=ok 但 bash 仍以
                    // exit_code=182 退出。根因已确认为 proot loader 的 MAP_FIXED 地址冲突
                    // （已在 proot 侧通过 fixup_load_addresses 修复）。
                    // 此探针保留用于回归验证。
                    let mypid = libc::getpid();
                    let setpgrp_rc = libc::tcsetpgrp(0, mypid);
                    if setpgrp_rc == 0 {
                        // 仅调试用: 这里必须与字面量真实长度一致；之前多写 1 字节会把相邻内存里的杂字节带进首帧，污染 182 退出样本。
                        let _ = libc::write(2, b",setpg=ok,sig54=dfl]\n".as_ptr() as *const _, 21); // 仅调试用
                    } else {
                        let errno = *libc::__errno_location();
                        let _ = libc::write(2, b",setpg=e".as_ptr() as *const _, 8);
                        // Write errno as decimal digits (async-signal-safe)
                        let mut buf = [0u8; 4];
                        let mut val = errno as u32;
                        let mut pos = buf.len();
                        loop {
                            pos -= 1;
                            buf[pos] = b'0' + (val % 10) as u8;
                            val /= 10;
                            if val == 0 { break; }
                        }
                        let _ = libc::write(2, buf[pos..].as_ptr() as *const _, (buf.len() - pos) as _);
                        let _ = libc::write(2, b"]\n".as_ptr() as *const _, 2);
                    }
                }

                Ok(())
            });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn '{}' failed: {}", program, e))?;
    tracing::info!( // 仅调试用
        "fallback_open_and_spawn spawn_ok child_pid={:?} {}", // 仅调试用
        child.process_id(), // 仅调试用
        fallback_detail, // 仅调试用
    ); // 仅调试用
    // 仅调试用: exit 182 根因已修复（proot fixup_load_addresses），但保留此
    // 探针用于回归验证。抓取子进程刚 spawn 后的 /proc/<pid>/status 快照。
    if let Some(child_pid) = child.process_id() { // 仅调试用
        tracing::warn!( // 仅调试用
            "PTY child immediate-snapshot pid={} {}", // 仅调试用
            child_pid, // 仅调试用
            collect_child_proc_snapshot(child_pid), // 仅调试用
        ); // 仅调试用
        spawn_child_status_probe(child_pid); // 仅调试用
    } // 仅调试用

    // Detach child stdio handles (master side is our I/O path)
    child.stdin.take();
    child.stdout.take();
    child.stderr.take();

    let master_pty = FallbackMasterPty {
        fd: master,
        took_writer: RefCell::new(false),
    };

    Ok((Box::new(master_pty), Box::new(child), fallback_detail))
}
