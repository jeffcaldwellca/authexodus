//! Keeping the computer awake while the proxy runs.
//!
//! Reinstalling Authy and waiting for its text message takes minutes with nobody touching
//! the computer. A laptop on battery would idle to sleep in that time, the proxy would stop
//! answering, and the iPhone or iPad, whose traffic all goes through it, would have no
//! internet. So for as long as the proxy runs, the system's own `caffeinate` is kept running
//! beside it:
//!
//! ```text
//! /usr/bin/caffeinate -i -w <this app's process id>
//! ```
//!
//! `-i` holds off idle sleep only: the display may still dim and lock, and closing the lid
//! still sleeps. `-w` makes `caffeinate` leave by itself when this app's process is gone, so
//! even a crash leaves nothing running. In the ordinary way it is stopped, and waited for,
//! when the proxy stops ([`KeepAwake`] does both when dropped).
//!
//! macOS only. Elsewhere [`KeepAwakeCommand::system`] is `None` and nothing is run.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The program that holds the computer awake, and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepAwakeCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl KeepAwakeCommand {
    /// What this system offers: `caffeinate` on a Mac, nothing anywhere else.
    pub fn system() -> Option<KeepAwakeCommand> {
        #[cfg(target_os = "macos")]
        {
            Some(KeepAwakeCommand {
                program: PathBuf::from("/usr/bin/caffeinate"),
                args: vec![
                    "-i".to_string(),
                    "-w".to_string(),
                    std::process::id().to_string(),
                ],
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }
}

/// A running keep-awake helper. Dropping it stops the helper and waits for it to be gone.
pub struct KeepAwake {
    child: Child,
}

impl KeepAwake {
    /// Start the helper. `None` when there is no command for this system or it cannot be
    /// started: the computer may then go to sleep, which is not a reason to refuse to run.
    pub fn start(command: Option<&KeepAwakeCommand>) -> Option<KeepAwake> {
        let command = command?;
        // The helper gets nothing of this app's: no environment, no open input or output.
        let spawned = Command::new(&command.program)
            .args(&command.args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match spawned {
            Ok(child) => {
                tracing::info!("the computer is being kept awake while the connection runs");
                Some(KeepAwake { child })
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the computer could not be kept awake; it may go to sleep during the run"
                );
                None
            }
        }
    }

    /// The helper's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        // Killing a process that has already left is fine; waiting collects it either way,
        // so no zombie is left behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
        tracing::debug!("the keep-awake helper was stopped");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Is there a process with this id? (Signal 0 delivers nothing; it only asks.)
    fn alive(pid: u32) -> bool {
        // SAFETY: `kill` with signal 0 has no effect on the target.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    #[test]
    fn the_helper_runs_while_held_and_is_gone_when_dropped() {
        let command = KeepAwakeCommand {
            program: PathBuf::from("/bin/sleep"),
            args: vec!["600".to_string()],
        };
        let awake = KeepAwake::start(Some(&command)).expect("the helper starts");
        let pid = awake.pid();
        assert!(alive(pid), "it runs while it is held");
        drop(awake);
        assert!(
            !alive(pid),
            "stopped and collected: nothing is left running"
        );
    }

    #[test]
    fn no_command_or_a_missing_program_is_not_an_error() {
        assert!(KeepAwake::start(None).is_none());
        let missing = KeepAwakeCommand {
            program: PathBuf::from("/nonexistent/authexodus-keep-awake"),
            args: vec![],
        };
        assert!(KeepAwake::start(Some(&missing)).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn on_a_mac_it_is_caffeinate_bound_to_this_process() {
        let command = KeepAwakeCommand::system().expect("a Mac has caffeinate");
        assert_eq!(command.program, PathBuf::from("/usr/bin/caffeinate"));
        assert_eq!(
            command.args,
            ["-i", "-w", &std::process::id().to_string()],
            "idle sleep only, and only for as long as this app lives"
        );
        assert!(command.program.exists());
    }
}
