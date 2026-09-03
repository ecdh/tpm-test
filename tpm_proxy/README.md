# TPM proxy (`tpm_proxy` & `tpm_proxy_lib`)

`tpm_proxy` is an extensible TCP proxy implementing the Microsoft TPM Simulator
(`mssim`) protocol. It allows any client configured with
`TPM2TOOLS_TCTI="mssim:..."` (e.g., `tpm2-tools`, `tpm2-pytss`, `tss-esapi`)
to communicate with different TPM backends.

## Architecture

1. **`//tpm_proxy:tpm_proxy_lib` (Rust library)**:
   - Exports the `TpmDevice` trait:
     ```rust
     pub trait TpmDevice: Send + 'static {
         fn transmit(&mut self, command: &[u8]) -> anyhow::Result<()>;
         fn receive(&mut self, response: &mut [u8]) -> anyhow::Result<usize>;
         fn handle_platform_command(&mut self, command: u32) -> anyhow::Result<u32> { Ok(0) }
         fn init(&mut self) -> anyhow::Result<()> { Ok(()) }
         fn shutdown(&mut self) -> anyhow::Result<()> { Ok(()) }
     }
     ```
   - Exports standard wire types and validation helpers: `TpmHeader`,
     `TPM_HEADER_SIZE` (10 bytes), and `ensure_buffer_capacity`.
   - Exports `MssimServer`: A multi-threaded TCP server handling TPM command
     (`port`) and platform (`port + 1`) connections, automatically invoking
     `init` on server initialization and `shutdown` on
     server termination.
   - Downstream repositories can implement `TpmDevice` for their hardware dev
     boards and build custom proxy binaries with zero MSSIM boilerplate.

2. **`//tpm_proxy:tpm_proxy` (CLI binary)**:
   - Bundles all built-in `TpmDevice` implementations.

## Supported device backends

- **`tcp` (`--device-type tcp`)**: Forwards traffic to an external TCP TPM
  simulator (`--tpm-host <ip:port>`).
- **`linux-dev` (`--device-type linux-dev`)**: Forwards traffic to a Linux TPM
  character device (`--dev-path /dev/tpmrm0` or `/dev/tpm0`).
- **`dynamic-tcti` (`--device-type dynamic-tcti`)**: Dynamically loads any C-ABI
  TCTI module via `tss2-tctildr` using `--tcti-conf <name|path.so>`.
- **`usb` (`--device-type usb`)**: Alias for `--device-type dynamic-tcti` with
  `--tcti-conf usb`.
- **`unix-socket` (`--device-type unix-socket`)**: Streams raw TPM 2.0 frames
  over a Unix domain socket (`--socket-path /tmp/tpm.sock`).
- **`mock` (`--device-type mock`)**: In-memory dummy responder (handles
  Startup, GetRandom, Hash) for unit testing.

## Usage examples

By default, the proxy binds securely to localhost (`127.0.0.1`). Use
`--bind-addr` to specify an alternate interface.

```bash
# Run in TCP mode forwarding to a simulator on 127.0.0.1:23210
bazel run //tpm_proxy -- \
  --device-type tcp \
  --port 2321 \
  --tpm-host 127.0.0.1:23210

# Run with Linux character device
bazel run //tpm_proxy -- \
  --device-type linux-dev \
  --dev-path /dev/tpmrm0 \
  --port 2321

# Run with Unix domain socket
bazel run //tpm_proxy -- \
  --device-type unix-socket \
  --socket-path /tmp/tpm.sock \
  --port 2321

# Run in Mock mode for unit testing
bazel run //tpm_proxy -- --device-type mock --port 2321
```

## Testing

Run unit tests for `tpm_proxy`:

```bash
bazel test //tpm_proxy:tpm_proxy_lib_test
```
