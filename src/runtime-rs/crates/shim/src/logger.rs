// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    os::unix::{fs::OpenOptionsExt, net::UnixDatagram},
    path::Path,
};

use anyhow::{Context, Result};

use crate::Error;

const SYSTEMD_JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

fn journal_socket_available(path: &Path) -> bool {
    UnixDatagram::unbound()
        .and_then(|socket| socket.connect(path))
        .is_ok()
}

fn containerd_log_destination(path: &str) -> Result<logging::LogDestination> {
    // Open the containerd shim log pipe read-write and non-blocking. Keeping a
    // read endpoint open prevents a containerd restart from turning the next
    // log write into EPIPE.
    let fifo = std::fs::OpenOptions::new()
        .custom_flags(libc::O_NONBLOCK)
        .create(true)
        .read(true)
        .write(true)
        .open(path)
        .context(Error::FileOpen(path.to_string()))?;

    Ok(logging::LogDestination::File(Box::new(fifo)))
}

pub(crate) fn set_logger(path: &str, sid: &str, is_debug: bool) -> Result<slog_async::AsyncGuard> {
    let level = if is_debug {
        slog::Level::Debug
    } else {
        slog::Level::Info
    };

    // systemd hosts receive a dedicated journal stream. Minimal or immutable
    // hosts such as Talos do not provide journald; keep their shim diagnostics
    // on containerd's existing log pipe instead of silently dropping them.
    let journal_available = journal_socket_available(Path::new(SYSTEMD_JOURNAL_SOCKET));
    let destination = if journal_available {
        logging::LogDestination::Journal
    } else {
        containerd_log_destination(path)?
    };
    let (logger, async_guard) =
        logging::create_logger_with_destination("kata-runtime", sid, level, destination);

    // not reset global logger when drop
    slog_scope::set_global_logger(logger).cancel_reset();

    let level = if is_debug {
        log::Level::Debug
    } else {
        log::Level::Info
    };
    slog_stdlog::init_with_level(level).context(format!("init with level {level}"))?;

    // Regist component loggers for later use, there loggers are set directly by configuration
    logging::register_component_logger("agent");
    logging::register_component_logger("runtimes");
    logging::register_component_logger("hypervisor");

    if !journal_available {
        warn!(
            slog_scope::logger(),
            "systemd journal unavailable; using containerd shim log pipe"
        );
    }

    Ok(async_guard)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram;

    use super::journal_socket_available;

    #[test]
    fn missing_journal_socket_uses_fallback() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!journal_socket_available(
            &directory.path().join("missing.sock")
        ));
    }

    #[test]
    fn reachable_journal_socket_is_selected_but_stale_socket_is_not() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("journal.sock");
        let socket = UnixDatagram::bind(&socket_path).unwrap();

        assert!(journal_socket_available(&socket_path));

        drop(socket);
        assert!(!journal_socket_available(&socket_path));
    }
}
