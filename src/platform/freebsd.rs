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
    remote_ssh_config_paths, set_default_plugin_pane_pwd, shutdown_client_stream,
    status_commands_supported, wait_client_stream_readable, write_client_stream,
    ClientStreamReader, StatusCommandGuard,
};

// Unlike CLOCK_UPTIME, FreeBSD's monotonic clock includes system suspend.
pub(super) const REMOTE_BRIDGE_CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

pub(crate) fn config_file_link_count(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(path)?.nlink())
}

pub(crate) fn check_config_write_target(_target: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn write_existing_config(_target: &Path, _contents: &[u8]) -> std::io::Result<bool> {
    Ok(false)
}

// The FreeBSD ACL API is not exposed by the libc crate. These opaque objects
// support both UFS POSIX ACLs and ZFS NFSv4 ACLs without translating either.
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut libc::c_void, kind: libc::c_int) -> libc::c_int;
    fn acl_is_trivial_np(acl: *mut libc::c_void, trivial: *mut libc::c_int) -> libc::c_int;
    fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
}

const ACL_TYPE_ACCESS: libc::c_int = 2;
const ACL_TYPE_NFS4: libc::c_int = 4;

struct ConfigAcl(*mut libc::c_void);

impl Drop for ConfigAcl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}

fn config_acl(fd: RawFd, kind: libc::c_int) -> std::io::Result<Option<ConfigAcl>> {
    let acl = unsafe { acl_get_fd_np(fd, kind) };
    if !acl.is_null() {
        return Ok(Some(ConfigAcl(acl)));
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EINVAL | libc::EOPNOTSUPP) => Ok(None),
        _ => Err(error),
    }
}

pub(crate) fn create_config_temporary(
    path: &Path,
    private: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    if private {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = std::fs::File::open(parent)?;
        if let Some(acl) = config_acl(directory.as_raw_fd(), ACL_TYPE_NFS4)? {
            let mut trivial = 0;
            if unsafe { acl_is_trivial_np(acl.0, &mut trivial) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // A named inherited NFSv4 grant can outlive chmod through an already
            // opened descriptor. Refuse such staging directories before creation.
            if trivial == 0 {
                return Err(std::io::Error::other(
                    "cannot safely stage private config in a directory with a nontrivial NFSv4 ACL",
                ));
            }
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if private { 0o600 } else { 0o666 })
        .open(path)
}

pub(crate) fn write_config_temporary(
    source: Option<&Path>,
    temporary: &Path,
    contents: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(temporary)?;
    if let Some(source) = source {
        let input = std::fs::File::open(source)?;
        let metadata = input.metadata()?;
        let current = output.metadata()?;
        if (metadata.uid(), metadata.gid()) != (current.uid(), current.gid())
            && unsafe { libc::fchown(output.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        for namespace in [libc::EXTATTR_NAMESPACE_USER, libc::EXTATTR_NAMESPACE_SYSTEM] {
            copy_config_attributes(input.as_raw_fd(), output.as_raw_fd(), namespace)?;
        }
        // Copy even trivial ACLs so destination inherited grants cannot survive.
        // Do this before enabling mode bits: chmod could unmask an inherited
        // POSIX grant and permit a descriptor that survives later ACL removal.
        let mut nfs4_acl = false;
        for kind in [ACL_TYPE_ACCESS, ACL_TYPE_NFS4] {
            if let Some(acl) = config_acl(input.as_raw_fd(), kind)? {
                if unsafe { acl_set_fd_np(output.as_raw_fd(), acl.0, kind) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                nfs4_acl |= kind == ACL_TYPE_NFS4;
            }
        }
        if nfs4_acl {
            // NFSv4 ACL assignment sets the ordinary mode bits. chmod afterward
            // can rewrite ordered allow/deny entries; reject uncommon special
            // mode bits we cannot preserve without changing the access policy.
            if output.metadata()?.mode() != metadata.mode() {
                return Err(std::io::Error::other(
                    "cannot preserve config mode without rewriting its NFSv4 ACL",
                ));
            }
        } else {
            output.set_permissions(metadata.permissions())?;
        }
    }
    output.write_all(contents)?;
    output.sync_all()
}

fn copy_config_attributes(
    source: RawFd,
    destination: RawFd,
    namespace: libc::c_int,
) -> std::io::Result<()> {
    let size = unsafe { libc::extattr_list_fd(source, namespace, std::ptr::null_mut(), 0) };
    if size < 0 {
        let error = std::io::Error::last_os_error();
        // SYSTEM attributes are privileged; FreeBSD denies enumeration instead of
        // filtering hidden labels as Linux does. Preserve them when permitted,
        // but ordinary users cannot inspect or transfer that namespace. Native
        // ACL copying remains mandatory and never uses this exception.
        if error.raw_os_error() == Some(libc::EOPNOTSUPP)
            || (namespace == libc::EXTATTR_NAMESPACE_SYSTEM
                && unsafe { libc::geteuid() } != 0
                && matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)))
        {
            return Ok(());
        }
        return Err(error);
    }
    let mut names = vec![0_u8; size as usize + 1];
    let count =
        unsafe { libc::extattr_list_fd(source, namespace, names.as_mut_ptr().cast(), names.len()) };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if count != size {
        return Err(std::io::Error::other(
            "config attribute list changed during copy",
        ));
    }
    names.truncate(count as usize);
    // FreeBSD returns length-prefixed names, not Linux's NUL-delimited list.
    let mut remaining = names.as_slice();
    while let Some((&length, rest)) = remaining.split_first() {
        let Some(name) = rest.get(..usize::from(length)) else {
            return Err(std::io::Error::other(
                "invalid extended attribute name list",
            ));
        };
        let name = std::ffi::CString::new(name).map_err(std::io::Error::other)?;
        remaining = &rest[usize::from(length)..];
        let size = unsafe {
            libc::extattr_get_fd(source, namespace, name.as_ptr(), std::ptr::null_mut(), 0)
        };
        if size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut value = vec![0_u8; size as usize + 1];
        let read = unsafe {
            libc::extattr_get_fd(
                source,
                namespace,
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if read != size {
            return Err(std::io::Error::other(
                "config attribute changed during copy",
            ));
        }
        value.truncate(read as usize);
        let written = unsafe {
            libc::extattr_set_fd(
                destination,
                namespace,
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
            )
        };
        if written < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if written as usize != value.len() {
            return Err(std::io::Error::other("short extended attribute write"));
        }
    }
    Ok(())
}

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

    unsafe extern "C" {
        fn acl_from_text(text: *const libc::c_char) -> *mut libc::c_void;
        fn acl_cmp_np(left: *mut libc::c_void, right: *mut libc::c_void) -> libc::c_int;
    }

    #[test]
    fn config_replacement_preserves_native_acl() {
        use std::os::fd::AsRawFd;
        let directory =
            std::env::temp_dir().join(format!("herdr-freebsd-native-acl-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        let temporary = directory.join("temporary");
        std::fs::write(&source, b"old").unwrap();
        let input = std::fs::File::open(&source).unwrap();
        let (kind, text) = if config_acl(input.as_raw_fd(), ACL_TYPE_NFS4)
            .unwrap()
            .is_some()
        {
            (ACL_TYPE_NFS4, c"owner@:rwxpDdaARWcCos::allow,user:65534:r::allow,group@:::allow,everyone@:::allow")
        } else {
            (
                ACL_TYPE_ACCESS,
                c"user::rw-,user:65534:r--,group::---,mask::r--,other::---",
            )
        };
        let acl = ConfigAcl(unsafe { acl_from_text(text.as_ptr()) });
        assert!(!acl.0.is_null());
        assert_eq!(
            unsafe { acl_set_fd_np(input.as_raw_fd(), acl.0, kind) },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        drop(create_config_temporary(&temporary, true).unwrap());
        write_config_temporary(Some(&source), &temporary, b"new").unwrap();
        let output = std::fs::File::open(&temporary).unwrap();
        let original = config_acl(input.as_raw_fd(), kind).unwrap().unwrap();
        let copied = config_acl(output.as_raw_fd(), kind).unwrap().unwrap();
        assert_eq!(unsafe { acl_cmp_np(original.0, copied.0) }, 0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn private_config_staging_rejects_nontrivial_nfs4_parent_before_creation() {
        use std::os::fd::AsRawFd;
        let directory =
            std::env::temp_dir().join(format!("herdr-freebsd-parent-acl-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let parent = std::fs::File::open(&directory).unwrap();
        if config_acl(parent.as_raw_fd(), ACL_TYPE_NFS4)
            .unwrap()
            .is_none()
        {
            std::fs::remove_dir(directory).unwrap();
            return;
        }
        let acl = ConfigAcl(unsafe {
            acl_from_text(c"owner@:rwxpDdaARWcCos::allow,user:65534:r:fd:allow,group@:::allow,everyone@:::allow".as_ptr())
        });
        assert!(!acl.0.is_null());
        assert_eq!(
            unsafe { acl_set_fd_np(parent.as_raw_fd(), acl.0, ACL_TYPE_NFS4) },
            0
        );
        let temporary = directory.join("temporary");
        assert!(create_config_temporary(&temporary, true).is_err());
        assert!(!temporary.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn config_replacement_preserves_mode_ownership_and_user_attributes() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        };
        let directory =
            std::env::temp_dir().join(format!("herdr-freebsd-config-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        let temporary = directory.join("temporary");
        std::fs::write(&source, b"old secret").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
        let input = std::fs::File::open(&source).unwrap();
        let value = b"preserved";
        assert_eq!(
            unsafe {
                libc::extattr_set_fd(
                    input.as_raw_fd(),
                    libc::EXTATTR_NAMESPACE_USER,
                    c"herdr-test".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                )
            },
            value.len() as isize
        );
        drop(create_config_temporary(&temporary, true).unwrap());
        assert_eq!(std::fs::metadata(&temporary).unwrap().mode() & 0o777, 0o600);
        write_config_temporary(Some(&source), &temporary, b"new secret").unwrap();
        let original = input.metadata().unwrap();
        let output = std::fs::File::open(&temporary).unwrap();
        let actual = output.metadata().unwrap();
        assert_eq!(
            (actual.uid(), actual.gid(), actual.mode()),
            (original.uid(), original.gid(), original.mode())
        );
        let mut copied = [0_u8; 9];
        assert_eq!(
            unsafe {
                libc::extattr_get_fd(
                    output.as_raw_fd(),
                    libc::EXTATTR_NAMESPACE_USER,
                    c"herdr-test".as_ptr(),
                    copied.as_mut_ptr().cast(),
                    copied.len(),
                )
            },
            value.len() as isize
        );
        assert_eq!(&copied, value);
        assert_eq!(std::fs::read(&source).unwrap(), b"old secret");
        assert_eq!(std::fs::read(&temporary).unwrap(), b"new secret");
        std::fs::remove_dir_all(directory).unwrap();
    }

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
