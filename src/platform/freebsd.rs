use std::os::fd::RawFd;

pub(crate) use super::unix_common::wait_client_stream_readable;

pub fn foreground_process_group_id_for_tty_fd(fd: RawFd) -> Option<u32> {
    let pgid = unsafe { libc::tcgetpgrp(fd) };
    (pgid > 0).then_some(pgid as u32)
}
