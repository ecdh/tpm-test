use anyhow::{anyhow, Context, Result};
use log::{info, warn};
use std::env;
use std::fs::{self, File};
use std::hash::{BuildHasher, Hasher};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn get_random_port() -> u16 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    hasher.write_u128(nanos);
    let rand = hasher.finish() as u32;
    let port = 1024 + (rand % (65535 - 1024));
    port as u16
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = path.metadata() {
            return metadata.permissions().mode() & 0o111 != 0;
        }
        false
    }
    #[cfg(not(unix))]
    true
}

/// Resolves a target binary's Bazel `short_path` to an executable on disk.
///
/// This function handles multiple Bazel execution contexts:
/// - Standard `bazel test` runs under Bzlmod where the root repository is `_main`.
/// - Downstream repositories consuming `tpm_test` as an external dependency,
///   where the workspace directory name differs from the local module name.
/// - Standalone execution or `bazel run` where `TEST_WORKSPACE` may be unset.
fn find_runfile(short_path: &str) -> Option<PathBuf> {
    // 1. Locate the Bazel runfiles directory from standard environment variables.
    let runfiles_dir = env::var("RUNFILES_DIR")
        .ok()
        .or_else(|| env::var("TEST_SRCDIR").ok());

    let mut paths_to_try = Vec::new();
    if let Some(ref dir) = runfiles_dir {
        let dir_path = Path::new(dir);

        // Try the explicit test workspace if set by Bazel.
        if let Ok(ws) = env::var("TEST_WORKSPACE") {
            paths_to_try.push(dir_path.join(&ws).join(short_path));
        }

        // Try standard Bzlmod root workspace (_main).
        paths_to_try.push(dir_path.join("_main").join(short_path));

        // Try directly under runfiles_dir (handles relative paths like ../+_repo_rules+...).
        paths_to_try.push(dir_path.join(short_path));

        // In downstream modules, scan all top-level workspace directories in RUNFILES_DIR
        // so the binary is found regardless of the consuming repository's name.
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    paths_to_try.push(entry.path().join(short_path));
                }
            }
        }
    }

    // 2. Check directories adjacent to the current test runner binary.
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            paths_to_try.push(parent.join(short_path));
            if let Some(grandparent) = parent.parent() {
                paths_to_try.push(grandparent.join(short_path));
            }
        }
    }

    // 3. Check relative to the current working directory.
    if let Ok(cwd) = env::current_dir() {
        paths_to_try.push(cwd.join(short_path));
    }

    // Test each candidate path in priority order for an existing executable file.
    for path in paths_to_try {
        if is_executable(&path) {
            return Some(path);
        }
    }

    // 4. Fallback: recursively search the entire runfiles tree for the binary filename.
    if let Some(ref dir) = runfiles_dir {
        let filename = Path::new(short_path).file_name()?;
        if let Some(path) = find_file_recursive(Path::new(dir), filename) {
            if is_executable(&path) {
                return Some(path);
            }
        }
    }

    None
}

fn find_file_recursive(dir: &Path, filename: &std::ffi::OsStr) -> Option<PathBuf> {
    if dir.is_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(found) = find_file_recursive(&path, filename) {
                        return Some(found);
                    }
                } else if path.file_name() == Some(filename) {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn is_port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(port: u16) -> Result<Self> {
        let mut path = env::temp_dir();
        path.push(format!("tpm_test_runner_{}_{}", std::process::id(), port));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        info!("Removing temporary directory: {}", self.path.display());
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn get_free_port_pair() -> Option<u16> {
    for _ in 0..10 {
        let port = get_random_port();
        if is_port_free(port) && is_port_free(port + 1) {
            return Some(port);
        }
    }
    None
}

struct ManagedMssimProcess {
    label: &'static str,
    binary_path_env: String,
    default_binary_runfiles: &'static [&'static str],
    extra_args: Vec<String>,
    port_flag: Option<String>,
    child: Option<Child>,
    temp_dir: Option<TempDir>,
}

impl ManagedMssimProcess {
    fn new(
        label: &'static str,
        binary_path_env: String,
        default_binary_runfiles: &'static [&'static str],
        extra_args: Vec<String>,
        port_flag: Option<String>,
    ) -> Self {
        Self {
            label,
            binary_path_env,
            default_binary_runfiles,
            extra_args,
            port_flag,
            child: None,
            temp_dir: None,
        }
    }

    fn setup(&mut self) -> Result<()> {
        let mut bin = if !self.binary_path_env.is_empty() {
            find_runfile(&self.binary_path_env)
        } else {
            None
        };
        if bin.is_none() {
            for default_runfile in self.default_binary_runfiles {
                if let Some(found) = find_runfile(default_runfile) {
                    bin = Some(found);
                    break;
                }
            }
        }
        let bin = bin.ok_or_else(|| {
            anyhow!(
                "Cannot find {} executable in runfiles: {}",
                self.label,
                if self.binary_path_env.is_empty() {
                    format!(
                        "(no path set, tried defaults: {:?})",
                        self.default_binary_runfiles
                    )
                } else {
                    self.binary_path_env.clone()
                }
            )
        })?;
        info!("Resolved {}: {}", self.label, bin.display());

        // The outer retry loop attempts full process lifecycle initialization up
        // to max_retries times. This guards against:
        // 1. TOCTOU port race conditions where another parallel test binds the
        //    candidate port between get_free_port_pair() checking it and the
        //    child process binding it.
        // 2. Transient process crashes or timeouts during binary startup.
        // Note: get_free_port_pair() handles fast internal candidate probing;
        // this outer loop handles full process spawn and readiness verification.
        let max_retries = 5;
        let log_file_name = format!("{}.log", self.label.to_lowercase());

        for attempt in 1..=max_retries {
            // Every simulator or proxy instance requires an isolated, dynamically
            // allocated port pair (command port and platform port = port + 1) to
            // prevent port collisions across concurrent Bazel test processes.
            let port = match get_free_port_pair() {
                Some(p) => p,
                None => {
                    if attempt < max_retries {
                        info!(
                            "Ports not free, retrying with new ports (attempt {})...",
                            attempt + 1
                        );
                        continue;
                    }
                    return Err(anyhow!(
                        "Cannot launch {}. Could not find free ports.",
                        self.label
                    ));
                }
            };

            let temp_dir = TempDir::new(port)?;
            info!(
                "Starting {} background process on port {} (platform {}) in isolated dir: {} (attempt {})",
                self.label,
                port,
                port + 1,
                temp_dir.path.display(),
                attempt
            );

            let log_path = temp_dir.path.join(&log_file_name);
            let log_file = File::create(&log_path)?;
            let err_file = log_file.try_clone()?;

            let mut cmd = Command::new(&bin);
            cmd.args(&self.extra_args);

            // Pass the allocated port to the process:
            // - If port_flag is Some(flag) (e.g. "--port" for tpm_proxy), pass
            //   the named flag followed by the port value.
            // - If port_flag is None (for reference Simulator), pass the port as
            //   a positional argument.
            if let Some(ref flag) = self.port_flag {
                if !flag.is_empty() {
                    cmd.arg(flag);
                }
            }
            cmd.arg(port.to_string())
                .current_dir(&temp_dir.path)
                .stdout(log_file)
                .stderr(err_file);

            let mut child = cmd
                .spawn()
                .with_context(|| format!("Failed to spawn {} process", self.label))?;

            info!("Waiting for {} to bind and initialize ports...", self.label);
            let mut success = false;
            let mut exited_early = false;
            let mut exit_status = None;

            for _ in 0..50 {
                // 50 * 100ms = 5s
                if let Ok(Some(status)) = child.try_wait() {
                    exited_early = true;
                    exit_status = Some(status);
                    break;
                }
                if TcpStream::connect(("127.0.0.1", port)).is_ok()
                    && TcpStream::connect(("127.0.0.1", port + 1)).is_ok()
                {
                    success = true;
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            if exited_early || !success {
                if log_path.exists() {
                    if let Ok(log_content) = fs::read_to_string(&log_path) {
                        warn!(
                            "{} log (failed attempt {}):\n{}",
                            self.label, attempt, log_content
                        );
                    }
                }

                let _ = child.kill();
                let _ = child.wait();

                if attempt < max_retries {
                    warn!(
                        "{} failed to start (exited_early={}, status={:?}), retrying with different ports...",
                        self.label, exited_early, exit_status
                    );
                    continue;
                } else {
                    return Err(anyhow!(
                        "{} failed to start after {} attempts.",
                        self.label,
                        max_retries
                    ));
                }
            }

            self.child = Some(child);
            self.temp_dir = Some(temp_dir);

            // Export standard TCTI environment variable so child test processes and
            // TSS libraries connect to this isolated process instance.
            env::set_var(
                "TPM2TOOLS_TCTI",
                format!("mssim:host=127.0.0.1,port={}", port),
            );
            info!(
                "Set connection TCTI to {} (mssim) on port {}",
                self.label.to_lowercase(),
                port
            );
            return Ok(());
        }

        Err(anyhow!(
            "Failed to start {} process after retries",
            self.label
        ))
    }
}

impl Drop for ManagedMssimProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            info!("Terminating {} background process...", self.label);
            let _ = child.kill();
            let _ = child.wait();
            info!("{} stopped cleanly.", self.label);
        }
    }
}

#[cfg(unix)]
#[allow(dead_code)]
mod sys_flock {
    //! Minimal FFI bindings for UNIX advisory file locking via `flock(2)`.
    //!
    //! Constants match `<sys/file.h>`. Kernel-managed advisory locks provide
    //! cross-process mutual exclusion across parallel Bazel test runners.

    use std::os::raw::c_int;

    /// Place a shared lock (reader lock). Multiple processes may hold a shared
    /// lock concurrently.
    pub const LOCK_SH: c_int = 1;

    /// Place an exclusive lock (writer lock). Only one process may hold an
    /// exclusive lock at any time, serializing access to shared hardware.
    pub const LOCK_EX: c_int = 2;

    /// Non-blocking modifier: combine with `LOCK_SH` or `LOCK_EX` to return
    /// immediately with `EWOULDBLOCK` if the lock is held elsewhere.
    pub const LOCK_NB: c_int = 4;

    /// Unlock: release an existing lock held by this file descriptor.
    pub const LOCK_UN: c_int = 8;

    extern "C" {
        /// Applies or removes an advisory lock on an open file (`<sys/file.h>`).
        pub fn flock(fd: c_int, operation: c_int) -> c_int;
    }
}

/// RAII guard providing cross-process mutual exclusion for shared hardware.
///
/// Acquires an exclusive kernel file lock (`LOCK_EX`) on a lockfile named
/// after `lock_id` (stored in `TPM_LOCK_DIR` or the system temp directory).
/// Automatically unlocks (`LOCK_UN`) on drop, and kernel automatically cleans
/// up locks if the process terminates unexpectedly.
pub struct DeviceLockGuard {
    lock_path: PathBuf,
    file: File,
}

impl DeviceLockGuard {
    /// Acquires an exclusive lock, blocking until the device is available.
    pub fn acquire(lock_id: &str) -> Result<Self> {
        Self::acquire_internal(lock_id, true)
    }

    /// Attempts to acquire an exclusive lock without blocking, returning an error
    /// if the device is currently in use.
    #[allow(dead_code)]
    pub fn try_acquire(lock_id: &str) -> Result<Self> {
        Self::acquire_internal(lock_id, false)
    }

    fn acquire_internal(lock_id: &str, blocking: bool) -> Result<Self> {
        let lock_dir = env::var("TPM_LOCK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| env::temp_dir());
        let lock_path = lock_dir.join(format!("tpm_proxy_{}.lock", lock_id));
        if blocking {
            info!(
                "Acquiring exclusive device lock on {}...",
                lock_path.display()
            );
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("Failed to open lock file {}", lock_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let op = if blocking {
                sys_flock::LOCK_EX
            } else {
                sys_flock::LOCK_EX | sys_flock::LOCK_NB
            };

            loop {
                let ret = unsafe { sys_flock::flock(fd, op) };
                if ret == 0 {
                    break;
                }
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                let msg = if !blocking {
                    format!("Device lock busy for {}: {}", lock_path.display(), err)
                } else {
                    format!(
                        "Failed to acquire exclusive lock on {}: {}",
                        lock_path.display(),
                        err
                    )
                };
                return Err(anyhow!(msg));
            }
        }

        if blocking {
            info!("Acquired exclusive device lock on {}", lock_path.display());
        }
        Ok(Self { lock_path, file })
    }
}

impl Drop for DeviceLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.file.as_raw_fd();
            unsafe {
                sys_flock::flock(fd, sys_flock::LOCK_UN);
            }
        }
        info!("Released device lock on {}", self.lock_path.display());
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let tpm_type = env::var("TPM_TYPE").unwrap_or_else(|_| "simulator".to_string());
    let simulator_path_env = env::var("SIMULATOR_PATH").unwrap_or_default();
    let proxy_path_env = env::var("PROXY_PATH").unwrap_or_default();
    let proxy_args_env = env::var("PROXY_ARGS").unwrap_or_default();
    let port_flag_env = env::var("PORT_FLAG").unwrap_or_else(|_| "--port".to_string());
    let dry_run = env::var("DRY_RUN")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);
    let test_command =
        env::var("TEST_COMMAND").context("TEST_COMMAND environment variable not set")?;

    let lock_id_env = env::var("TPM_LOCK_ID").ok().filter(|s| !s.is_empty());

    info!("TPM Test Runner initializing:");
    info!("  TPM_TYPE:     {}", tpm_type);
    if let Some(ref lock_id) = lock_id_env {
        info!("  LOCK_ID:      {}", lock_id);
    }
    info!("  TEST_COMMAND: {}", test_command);
    if dry_run {
        info!("  DRY_RUN:      true");
    }
    if tpm_type == "simulator" {
        info!("  SIMULATOR:    {}", simulator_path_env);
    } else if tpm_type == "proxy" {
        info!("  PROXY:        {}", proxy_path_env);
    }

    struct Level2TeardownGuard {
        tool_path: Option<String>,
    }

    impl Drop for Level2TeardownGuard {
        fn drop(&mut self) {
            if let Some(ref path) = self.tool_path {
                if !path.is_empty() {
                    if let Some(tool) = find_runfile(path) {
                        info!(
                            "Executing Level 2 post-test teardown tool: {}",
                            tool.display()
                        );
                        match Command::new(&tool).status() {
                            Ok(status) => {
                                if !status.success() {
                                    log::error!(
                                        "Level 2 teardown_tool exited with non-zero status: {:?}",
                                        status
                                    );
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to execute Level 2 teardown_tool ({}): {:?}",
                                    path,
                                    e
                                );
                            }
                        }
                    } else {
                        log::error!("Cannot find Level 2 teardown_tool in runfiles: {}", path);
                    }
                }
            }
        }
    }

    let (_device_lock, _teardown_guard, _env) = if dry_run {
        info!("[DRY RUN] Skipping TPM environment, device lock, and setup/teardown hooks.");
        (None, None, None)
    } else {
        let setup_tool_env = env::var("SETUP_TOOL").ok();
        let teardown_tool_env = env::var("TEARDOWN_TOOL").ok();

        let device_lock = if let Some(ref lock_id) = lock_id_env {
            Some(DeviceLockGuard::acquire(lock_id)?)
        } else {
            None
        };

        let teardown_guard = Some(Level2TeardownGuard {
            tool_path: teardown_tool_env,
        });

        if let Some(ref path) = setup_tool_env {
            if !path.is_empty() {
                let tool = find_runfile(path).ok_or_else(|| {
                    anyhow!("Cannot find Level 2 setup_tool in runfiles: {}", path)
                })?;
                info!("Executing Level 2 pre-test setup tool: {}", tool.display());
                let status = Command::new(&tool)
                    .status()
                    .context("Failed to execute Level 2 setup_tool")?;
                if !status.success() {
                    return Err(anyhow!(
                        "Level 2 setup_tool failed with status: {:?}",
                        status
                    ));
                }
            }
        }

        let mut env = match tpm_type.as_str() {
            "simulator" => ManagedMssimProcess::new(
                "Simulator",
                simulator_path_env,
                &[
                    "third_party/tcg_tpm/tcg_tpm",
                    "third_party/tcg_tpm/Simulator",
                ],
                vec![],
                None,
            ),
            "proxy" => {
                let proxy_args: Vec<String> = if proxy_args_env.is_empty() {
                    Vec::new()
                } else {
                    proxy_args_env
                        .split("@@TPM_ARG@@")
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect()
                };
                ManagedMssimProcess::new(
                    "Proxy",
                    proxy_path_env,
                    &["tpm_proxy/tpm_proxy"],
                    proxy_args,
                    Some(port_flag_env),
                )
            }
            other => {
                return Err(anyhow!(
                    "Unsupported TPM_TYPE: '{}'. Expected 'simulator' or 'proxy'.",
                    other
                ));
            }
        };

        env.setup()?;
        (device_lock, teardown_guard, Some(env))
    };

    let cmd = find_runfile(&test_command)
        .ok_or_else(|| anyhow!("Cannot find test command in runfiles: {}", test_command))?;
    let mut args: Vec<String> = env::args().skip(1).collect();
    if dry_run && !args.iter().any(|a| a == "--nocapture") {
        args.push("--nocapture".to_string());
    }
    info!(
        "Executing test command: {} with args {:?}",
        cmd.display(),
        args
    );
    let status = Command::new(&cmd)
        .args(&args)
        .status()
        .context("Failed to execute test command")?;
    if !status.success() {
        return Err(anyhow!("Test command failed with status: {:?}", status));
    }
    info!("Test completed successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_lock_mutual_exclusion() -> Result<()> {
        let lock_id = format!("test_lock_{}", std::process::id());

        // 1. First acquisition succeeds
        let guard1 = DeviceLockGuard::acquire(&lock_id)?;

        // 2. Second non-blocking acquisition on same lock_id fails (busy)
        let attempt2 = DeviceLockGuard::try_acquire(&lock_id);
        assert!(
            attempt2.is_err(),
            "Second lock must fail while first is held"
        );

        // 3. Releasing guard1 allows second acquisition to succeed
        drop(guard1);
        let guard2 = DeviceLockGuard::try_acquire(&lock_id)?;
        drop(guard2);

        // Clean up the lock file
        let lock_dir = env::var("TPM_LOCK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| env::temp_dir());
        let _ = fs::remove_file(lock_dir.join(format!("tpm_proxy_{}.lock", lock_id)));

        Ok(())
    }

    #[test]
    fn test_device_lock_different_ids() -> Result<()> {
        let lock_id_1 = format!("test_lock_a_{}", std::process::id());
        let lock_id_2 = format!("test_lock_b_{}", std::process::id());

        // Locks on different IDs must not block each other
        let guard1 = DeviceLockGuard::acquire(&lock_id_1)?;
        let guard2 = DeviceLockGuard::try_acquire(&lock_id_2);
        assert!(
            guard2.is_ok(),
            "Distinct lock IDs must not block each other"
        );

        drop(guard1);
        drop(guard2);

        let lock_dir = env::var("TPM_LOCK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| env::temp_dir());
        let _ = fs::remove_file(lock_dir.join(format!("tpm_proxy_{}.lock", lock_id_1)));
        let _ = fs::remove_file(lock_dir.join(format!("tpm_proxy_{}.lock", lock_id_2)));

        Ok(())
    }
}
