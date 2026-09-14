# TPM test runner

`tpm_test_runner` is a test execution framework and orchestration harness for
Trusted Platform Module 2.0 (TPM 2.0) tests under Bazel. It manages test
execution against ephemeral local simulator instances, TCP proxy processes, or
hardware TPMs, providing dynamic TCP port allocation, test isolation,
environment variable configuration, advisory hardware locking, and
setup/teardown lifecycle hooks.

## Features

- **Dynamic simulator and proxy orchestration**: Automatically starts and
  manages an isolated instance of the TCG TPM 2.0 simulator (`tcg_tpm`) or
  a TPM proxy (`tpm_proxy`) on dynamically allocated command and platform TCP
  ports, preventing port collisions during parallel test execution.
- **Hardware mutual exclusion (`DeviceLockGuard`)**: Implements RAII exclusive
  advisory file locking (`flock`) on a configurable `lock_id`. Guarantees
  mutual exclusion for tests sharing the same hardware resource while allowing
  tests with different lock IDs to run in parallel.
- **Pluggable test environments**: Supports late-bound environment selection
  via Starlark rules and Bazel `label_flag`.
- **Generic test wrapping**: `tpm_wrapped_test` and `tpm_test_suite` allow
  wrapping any executable test target (`rust_test`, `cc_test`, `sh_test`) with
  automatic environment setup and user tag propagation.
- **Two-level lifecycle hooks**:
  - *Level 1 (Device/proxy)*: `init` and `shutdown` hooks on the `TpmDevice`
    trait in `tpm_proxy`.
  - *Level 2 (Test runner)*: `setup_tool` and `teardown_tool` executables
    invoked before and after test execution with RAII cleanup guarantees.

## Starlark rules and macros

The package exports Starlark rules in `tpm_env.bzl` and `tpm_test.bzl`:

### Environment rules (`tpm_env.bzl`)

- `tpm_simulator_environment`: Defines a simulator environment target. Provides
  `TpmEnvInfo` with `TPM_TYPE=simulator`, dynamic ports, and runfiles for the
  simulator binary.
- `tpm_proxy_environment`: Defines a TPM proxy environment target for hardware
  devboards, Unix sockets, or mock devices. Configures proxy arguments, port
  flags, hardware tags (`is_hardware`), and advisory lock IDs (`lock_id`).
- `TpmEnvInfo`: Starlark provider conveying environment variables and required
  runfiles to test wrappers.

### Test rules and macros (`tpm_test.bzl`)

- `tpm_wrapped_test`: Wraps an arbitrary test binary (`test_binary`) with the
  test runner orchestration script, dynamic ports, and lifecycle tools.
- `tpm_test_suite`: Generates a collection of `tpm_wrapped_test` targets from a
  list or dictionary of test targets with parameterized arguments, propagating
  custom tags (such as `no-sandbox`) and supporting environment overrides.

### Build setting flag

- `//tpm_test_runner:tpm_environment`: A `label_flag` whose default value is
  `//tpm_test_runner:simulator`. You can switch environments across the entire
  build or per test via command-line flags:
  ```bash
  bazel test //... \
    --//tpm_test_runner:tpm_environment=//tpm_test_runner:simulator
  ```

## Usage examples

### Wrapping a test target

In your `BUILD.bazel`:

```starlark
load("@tpm_test//tpm_test_runner:tpm_test.bzl", "tpm_wrapped_test")

rust_test(
    name = "my_tpm_test_bin",
    srcs = ["my_tpm_test.rs"],
    deps = ["@rust_crates//:tss-esapi-sys"],
)

tpm_wrapped_test(
    name = "my_tpm_test",
    test_binary = ":my_tpm_test_bin",
)
```

Run the wrapped test with Bazel:

```bash
bazel test //path/to:my_tpm_test
```

### Defining a test suite

```starlark
load("@tpm_test//tpm_test_runner:tpm_test.bzl", "tpm_test_suite")

tpm_test_suite(
    name = "integration_tests",
    tests = [
        ":pcr_test_bin",
        ":nv_test_bin",
    ],
)
```

## Downstream integration guide: testing with custom hardware TPM proxies

Downstream repositories targeting physical hardware TPMs (e.g., devboards over
USB, SPI, I2C, or PCIe) can integrate with this test framework seamlessly
without modifying or duplicating test code.

### 1. Implement downstream proxy binary

Downstream implements the `TpmDevice` trait from
`@tpm_test//tpm_proxy:tpm_proxy_lib` and runs `MssimServer`:

```rust
use anyhow::Result;
use clap::Parser;
use tpm_proxy_lib::{MssimServer, TpmDevice};

struct DownstreamHwDevice {
    device_path: String,
}

impl TpmDevice for DownstreamHwDevice {
    fn transmit(&mut self, command: &[u8]) -> Result<()> {
        // Send raw TPM 2.0 command frame to hardware
        Ok(())
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize> {
        // Read raw TPM 2.0 response frame from hardware
        Ok(0)
    }

    fn init(&mut self) -> Result<()> {
        // Optional: Board power-cycle or reset before test starts
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        // Optional: Clean up board state after test completes
        Ok(())
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 2321)]
    port: u16,

    #[arg(long, default_value = "/dev/tpm0")]
    device_path: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dev = DownstreamHwDevice {
        device_path: args.device_path,
    };
    let server = MssimServer::new("127.0.0.1", args.port, Box::new(dev))?;
    server.run()
}
```

Define the proxy binary in downstream `BUILD.bazel`:

```starlark
load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "downstream_tpm_proxy",
    srcs = ["src/main.rs"],
    deps = [
        "@rust_crates//:anyhow",
        "@rust_crates//:clap",
        "@tpm_test//tpm_proxy:tpm_proxy_lib",
    ],
)
```

### 2. Define the test environment target

In downstream's `BUILD.bazel`, load `tpm_proxy_environment`:

```starlark
load("@tpm_test//tpm_test_runner:tpm_env.bzl", "tpm_proxy_environment")

tpm_proxy_environment(
    name = "hw_board_env",
    is_hardware = True,
    lock_id = "hw_board_0",
    port_flag = "--port",
    proxy_args = [
        "--device-path",
        "/dev/tpm0",
    ],
    proxy_bin = ":downstream_tpm_proxy",
)
```

### 3. Run tests against the environment

#### Method A: Late-binding existing upstream tests

Run test suites directly against downstream's hardware proxy by overriding the
`tpm_environment` build setting:

```bash
bazel test @tpm_test//tests:all \
  --@tpm_test//tpm_test_runner:tpm_environment=//my_package:hw_board_env \
  --test_strategy=local
```

- `tpm_test_runner` acquires the exclusive device lock on `hw_board_0`.
- Spawns downstream's proxy on an allocated free port.
- Configures `TPM2TOOLS_TCTI` to connect to the proxy over MSSIM.
- Runs the test suite sequentially without inter-test collisions.
- Automatically cleans up the proxy and releases the lock on teardown.

#### Method B: Defining downstream test targets

Downstream can wrap custom test binaries using `tpm_wrapped_test`:

```starlark
load("@tpm_test//tpm_test_runner:tpm_test.bzl", "tpm_wrapped_test")

tpm_wrapped_test(
    name = "firmware_validation_test_wrapped",
    environment = ":hw_board_env",
    tags = ["no-sandbox"],
    test_binary = ":firmware_validation_test",
)
```

#### Method C: Multi-board test farm concurrency

If downstream connects multiple physical boards to a test station, define an
environment per board with distinct `lock_id` values:

```starlark
tpm_proxy_environment(
    name = "board_0_env",
    is_hardware = True,
    lock_id = "board_0",
    proxy_args = ["--device-path", "/dev/tpm0"],
    proxy_bin = ":downstream_tpm_proxy",
)

tpm_proxy_environment(
    name = "board_1_env",
    is_hardware = True,
    lock_id = "board_1",
    proxy_args = ["--device-path", "/dev/tpm1"],
    proxy_bin = ":downstream_tpm_proxy",
)

tpm_test_suite(
    name = "board_0_tests",
    environment = ":board_0_env",
    tags = ["no-sandbox"],
    tests = [":board_test"],
)

tpm_test_suite(
    name = "board_1_tests",
    environment = ":board_1_env",
    tags = ["no-sandbox"],
    tests = [":board_test"],
)
```

Running both test suites in parallel:

```bash
bazel test //my_package:board_0_tests //my_package:board_1_tests \
  --local_test_jobs=2
```

Tests targeting Board 0 serialize on `board_0.lock`, tests targeting Board 1
serialize on `board_1.lock`, and Board 0 and Board 1 execute concurrently.
