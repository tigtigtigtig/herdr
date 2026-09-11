use std::ffi::OsStr;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use super::unix_desktop::{
    open_url, read_clipboard_image, read_clipboard_text, show_desktop_notification, write_clipboard,
};
use super::{ForegroundJob, ForegroundProcess, Signal};

pub(crate) use super::unix_common::{
    configure_status_command, create_remote_private_dir, create_remote_ssh_config_dir,
    create_remote_ssh_config_file, hostname, local_datetime, remote_bridge_endpoint_path,
    remote_private_temp_base, remote_reattach_argument, remote_reattach_program,
    remote_ssh_config_paths, set_default_plugin_pane_pwd, status_commands_supported,
    wait_client_stream_readable, StatusCommandGuard,
};

const SERVER_NOFILE_LIMIT_TARGET: libc::rlim_t = 8192;

pub(crate) fn should_draw_host_cursor_by_default() -> bool {
    false
}
pub(crate) fn should_query_host_terminal_palette() -> bool {
    true
}

fn raw_command_argv(command: &str, flag: &str) -> Vec<std::ffi::OsString> {
    vec!["/bin/sh".into(), flag.into(), command.into()]
}

pub(crate) fn detached_custom_command_process_platform(command: &str) -> Command {
    let argv = raw_command_argv(command, "-lc");
    let mut process = Command::new(&argv[0]);
    process.args(&argv[1..]);
    process
}

pub(crate) fn pane_custom_command_pty_builder_platform(
    command: &str,
) -> portable_pty::CommandBuilder {
    portable_pty::CommandBuilder::from_argv(raw_command_argv(command, "-c"))
}

pub(crate) fn scrollback_editor_argv(path: &Path) -> std::io::Result<Vec<String>> {
    let quoted_path = shell_quote(&path.display().to_string());
    let command = format!(
        r#"scrollback_file={quoted_path}; eval "${{EDITOR:-vi}} \"\$scrollback_file\""; status=$?; rm -f "$scrollback_file"; exit $status"#
    );
    Ok(vec!["/bin/sh".to_string(), "-c".to_string(), command])
}

pub(crate) fn interactive_shell_command(argv: &[String], shell_name: &str) -> Option<String> {
    super::interactive_unix_shell_command(argv, shell_name, shell_quote)
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '@' | '%' | '_' | '+' | '=' | ':' | ',' | '.' | '/' | '-'
                )
        })
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn raise_server_nofile_limit() {
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        tracing::warn!(err = %std::io::Error::last_os_error(), "failed to read server file descriptor limit");
        return;
    }
    let target = if limit.rlim_max == libc::RLIM_INFINITY {
        SERVER_NOFILE_LIMIT_TARGET
    } else {
        SERVER_NOFILE_LIMIT_TARGET.min(limit.rlim_max)
    };
    if limit.rlim_cur >= target {
        return;
    }
    let previous = limit.rlim_cur;
    limit.rlim_cur = target;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        tracing::warn!(err = %std::io::Error::last_os_error(), "failed to raise server file descriptor limit");
    } else {
        tracing::info!(previous, target, "raised server file descriptor soft limit");
    }
}

fn positive_pid(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok().filter(|pid| *pid > 0)
}

// Kernel responses may race process creation; retry only a bounded number of times.
fn sysctl_bytes(mib: &mut [libc::c_int]) -> Option<Vec<u8>> {
    for _ in 0..3 {
        let mut len = 0usize;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
            || len == 0
        {
            return None;
        }
        let mut bytes = vec![0u8; len];
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                bytes.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            bytes.truncate(len);
            return Some(bytes);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

fn process_info(pid: u32) -> Option<libc::kinfo_proc> {
    let pid = positive_pid(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // A single-process probe runs once per pane detection poll. Keep it to one
    // syscall and a stack record instead of allocating a process-table buffer.
    let mut info: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&info);
    // SAFETY: info is aligned and writable for exactly len bytes; no new value
    // is supplied, so sysctl only reads kernel state into our record.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            (&mut info as *mut libc::kinfo_proc).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || len != std::mem::size_of_val(&info)
    {
        return None;
    }
    (info.ki_structsize as usize == std::mem::size_of::<libc::kinfo_proc>() && info.ki_pid == pid)
        .then_some(info)
}

fn kinfo_processes(selector: libc::c_int, id: u32) -> Vec<libc::kinfo_proc> {
    let Some(id) = positive_pid(id) else {
        return Vec::new();
    };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, selector, id];
    let Some(bytes) = sysctl_bytes(&mut mib) else {
        return Vec::new();
    };
    let size = std::mem::size_of::<libc::kinfo_proc>();
    bytes
        .chunks_exact(size)
        // SAFETY: chunks_exact yields a full record; unaligned copies avoid
        // assuming Vec<u8> has the alignment of kinfo_proc.
        .map(|bytes| unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::kinfo_proc>()) })
        .filter(|info| info.ki_structsize as usize == size && info.ki_pid > 0)
        .collect()
}

fn process_name(info: &libc::kinfo_proc) -> Option<String> {
    let bytes = info.ki_comm.map(|byte| byte as u8);
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let name = String::from_utf8_lossy(&bytes[..end]).into_owned();
    (!name.is_empty()).then_some(name)
}

fn process_nul_strings(pid: u32, selector: libc::c_int) -> Option<Vec<String>> {
    let pid = positive_pid(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, selector, pid];
    let bytes = sysctl_bytes(&mut mib)?;
    let values = bytes
        .strip_suffix(&[0])
        .unwrap_or(&bytes)
        .split(|byte| *byte == 0)
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect::<Vec<_>>();
    (!values.is_empty()).then_some(values)
}

fn process_argv(pid: u32) -> Option<Vec<String>> {
    process_nul_strings(pid, libc::KERN_PROC_ARGS)
}

fn foreground_job_for_group(process_group_id: u32) -> Option<ForegroundJob> {
    let processes = kinfo_processes(libc::KERN_PROC_PGRP, process_group_id)
        .into_iter()
        .filter_map(|info| {
            let pid = u32::try_from(info.ki_pid).ok()?;
            let name = process_name(&info)?;
            let argv = process_argv(pid);
            Some(ForegroundProcess {
                pid,
                name,
                argv0: argv.as_ref().and_then(|args| args.first()).cloned(),
                cmdline: argv.as_ref().map(|args| args.join(" ")),
                argv,
            })
        })
        .collect::<Vec<_>>();
    (!processes.is_empty()).then_some(ForegroundJob {
        process_group_id,
        processes,
    })
}

pub(crate) fn available_pane_shell(child_pid: u32) -> Option<String> {
    super::available_pane_shell_from_job(child_pid, foreground_job(child_pid)?)
}

pub fn foreground_job(child_pid: u32) -> Option<ForegroundJob> {
    foreground_job_for_group(foreground_process_group_id(child_pid)?)
}

pub fn foreground_group_leader_job(process_group_id: u32) -> Option<ForegroundJob> {
    let info = process_info(process_group_id)?;
    if info.ki_pgid <= 0 || info.ki_pgid as u32 != process_group_id {
        return None;
    }
    let argv = process_argv(process_group_id);
    Some(ForegroundJob {
        process_group_id,
        processes: vec![ForegroundProcess {
            pid: process_group_id,
            name: process_name(&info)?,
            argv0: argv.as_ref().and_then(|args| args.first()).cloned(),
            cmdline: argv.as_ref().map(|args| args.join(" ")),
            argv,
        }],
    })
}

pub fn foreground_process_group_id(child_pid: u32) -> Option<u32> {
    let tpgid = process_info(child_pid)?.ki_tpgid;
    (tpgid > 0).then_some(tpgid as u32)
}

pub fn foreground_process_group_id_for_tty_fd(fd: RawFd) -> Option<u32> {
    let pgid = unsafe { libc::tcgetpgrp(fd) };
    (pgid > 0).then_some(pgid as u32)
}

pub fn process_cwd(pid: u32) -> Option<PathBuf> {
    let pid = positive_pid(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_CWD, pid];
    let bytes = sysctl_bytes(&mut mib)?;
    if bytes.len() < std::mem::size_of::<libc::kinfo_file>() {
        return None;
    }
    let info = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::kinfo_file>()) };
    let bytes = info.kf_path.map(|byte| byte as u8);
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let path = &bytes[..end];
    (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path)))
}

pub fn process_agent_hint(pid: u32) -> Option<crate::detect::Agent> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_ENV,
        positive_pid(pid)?,
    ];
    super::parse_agent_env_hint(&sysctl_bytes(&mut mib)?)
}

pub fn session_processes(child_pid: u32) -> Vec<u32> {
    let Some(info) = process_info(child_pid) else {
        return Vec::new();
    };
    let Ok(session_id) = u32::try_from(info.ki_sid) else {
        return Vec::new();
    };
    kinfo_processes(libc::KERN_PROC_SESSION, session_id)
        .into_iter()
        .filter_map(|info| u32::try_from(info.ki_pid).ok())
        .collect()
}

pub fn signal_processes(pids: &[u32], signal: Signal) {
    let signal = match signal {
        Signal::Hangup => libc::SIGHUP,
        Signal::Terminate => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    };
    for &pid in pids {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            if pid > 0 {
                unsafe { libc::kill(pid, signal) };
            }
        }
    }
}

pub fn process_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    pid > 0
        && (unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn isolated_child_preserves_arguments_environment_and_group_identity() {
        use std::io::Read;

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf ready; read answer", "marker", "", "two words"]);
        command.env("HERDR_AGENT", "codex").current_dir("/tmp");
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        super::super::detach_server_daemon_command(&mut command);
        let mut child = ChildGuard(command.spawn().expect("isolated shell"));
        let mut ready = [0; 5];
        child
            .0
            .stdout
            .as_mut()
            .expect("stdout")
            .read_exact(&mut ready)
            .expect("ready");
        let pid = child.0.id();
        assert_eq!(process_cwd(pid), Some(PathBuf::from("/tmp")));
        let argv = process_argv(pid).expect("argv");
        assert_eq!(&argv[argv.len() - 3..], &["marker", "", "two words"]);
        assert_eq!(process_agent_hint(pid), Some(crate::detect::Agent::Codex));
        assert_eq!(session_processes(pid), vec![pid]);
        let job = foreground_group_leader_job(pid).expect("leader");
        assert_eq!(job.processes.len(), 1);
        assert_eq!(job.processes[0].pid, pid);
        signal_processes(&[pid], Signal::Terminate);
        let status = child.0.wait().expect("reaped");
        assert!(!status.success());
        assert!(!process_exists(pid));
    }

    #[test]
    fn invalid_process_ids_do_not_address_the_callers_group() {
        for pid in [0, u32::MAX] {
            assert!(!process_exists(pid));
            assert!(process_info(pid).is_none());
            assert!(process_cwd(pid).is_none());
            assert!(process_agent_hint(pid).is_none());
            assert!(session_processes(pid).is_empty());
            signal_processes(&[pid], Signal::Kill);
        }
    }

    #[test]
    fn sysctl_reads_current_process_metadata() {
        let pid = std::process::id();
        let info = process_info(pid).expect("current process info");
        assert_eq!(u32::try_from(info.ki_pid).ok(), Some(pid));
        assert!(process_exists(pid));
        assert!(process_cwd(pid).is_some());
        assert!(session_processes(pid).contains(&pid));
    }

    #[test]
    fn process_arguments_include_test_binary() {
        assert!(!process_argv(std::process::id())
            .expect("current process arguments")
            .is_empty());
    }
}
