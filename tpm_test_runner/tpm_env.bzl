TpmEnvInfo = provider(
    doc = "Contains information about the TPM test environment.",
    fields = {
        "env": "A dictionary of environment variables to set for the test.",
        "runfiles": "A runfiles object containing runtime files required by this environment.",
    },
)

def _tpm_simulator_environment_impl(ctx):
    simulator_bin = ctx.executable.simulator_bin
    env = {
        "SIMULATOR_PATH": simulator_bin.short_path,
        "TPM_TYPE": "simulator",
    }
    if ctx.attr.dry_run:
        env["DRY_RUN"] = "true"
    return [
        TpmEnvInfo(
            env = env,
            runfiles = ctx.runfiles(
                files = [simulator_bin],
                collect_default = True,
            ),
        ),
    ]

tpm_simulator_environment = rule(
    doc = "Defines a TPM simulator environment.",
    implementation = _tpm_simulator_environment_impl,
    attrs = {
        "dry_run": attr.bool(
            default = False,
            doc = "Whether to run in dry-run mode.",
        ),
        "simulator_bin": attr.label(
            cfg = "target",
            default = Label("//third_party/tcg_tpm:tcg_tpm"),
            doc = "The TCG Simulator binary target.",
            executable = True,
        ),
    },
)

def _tpm_proxy_environment_impl(ctx):
    proxy_bin = ctx.executable.proxy_bin

    env = {
        "PORT_FLAG": ctx.attr.port_flag,
        "PROXY_PATH": proxy_bin.short_path,
        "TPM_TYPE": "proxy",
    }
    if ctx.attr.dry_run:
        env["DRY_RUN"] = "true"
    if ctx.attr.is_hardware:
        env["TPM_IS_HARDWARE"] = "true"
    if ctx.attr.lock_id:
        env["TPM_LOCK_ID"] = ctx.attr.lock_id
    if ctx.attr.lock_dir:
        env["TPM_LOCK_DIR"] = ctx.attr.lock_dir
    if ctx.attr.proxy_args:
        # Delimit args using @@TPM_ARG@@ to safely preserve whitespace and arguments.
        env["PROXY_ARGS"] = "@@TPM_ARG@@".join(ctx.attr.proxy_args)
    env.update(ctx.attr.env)

    return [
        TpmEnvInfo(
            env = env,
            runfiles = ctx.runfiles(
                files = [proxy_bin] + ctx.files.data,
                collect_default = True,
            ),
        ),
    ]

tpm_proxy_environment = rule(
    doc = "Defines a TPM proxy environment for test execution.",
    implementation = _tpm_proxy_environment_impl,
    attrs = {
        "data": attr.label_list(
            allow_files = True,
            doc = "Additional data or runfiles required by the proxy binary.",
        ),
        "dry_run": attr.bool(
            default = False,
            doc = "Whether to run in dry-run mode.",
        ),
        "env": attr.string_dict(
            default = {},
            doc = "Optional additional environment variables for the proxy execution.",
        ),
        "is_hardware": attr.bool(
            default = False,
            doc = "Whether the proxy targets physical hardware (skips destructive flash wear-out tests).",
        ),
        "lock_dir": attr.string(
            default = "",
            doc = "Optional directory where lock files are created. Defaults to system temp directory.",
        ),
        "lock_id": attr.string(
            default = "",
            doc = "Optional device lock identifier to enforce exclusive/sequential execution across tests targeting the same hardware device.",
        ),
        "port_flag": attr.string(
            default = "--port",
            doc = "Flag used to pass the command listening port to the proxy binary.",
        ),
        "proxy_args": attr.string_list(
            default = [],
            doc = "Command-line arguments to pass to the proxy binary.",
        ),
        "proxy_bin": attr.label(
            cfg = "target",
            default = Label("//tpm_proxy:tpm_proxy"),
            doc = "The TPM proxy executable binary (built-in tpm_proxy or downstream implementation).",
            executable = True,
        ),
    },
)
