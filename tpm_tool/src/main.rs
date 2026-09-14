use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use std::net::SocketAddr;
use tpm_test_support::TpmClient;

mod command;
use crate::command::Dispatch;

#[derive(Parser, Debug)]
enum RootCommandHierarchy {
    NoOp(command::NoOp),
    GetRandom(command::random::GetRandom),
    Hash(command::hash::Hash),
    #[command(subcommand)]
    Pcr(command::pcr::Pcr),
    #[command(subcommand)]
    Ecdsa(command::ecdsa::Ecdsa),
    #[command(subcommand)]
    Ek(command::ek::Ek),
    Quote(command::quote::Quote),
    Startup(command::startup::Startup),
}

impl Dispatch for RootCommandHierarchy {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        match self {
            Self::NoOp(cmd) => cmd.run(client),
            Self::GetRandom(cmd) => cmd.run(client),
            Self::Hash(cmd) => cmd.run(client),
            Self::Pcr(cmd) => cmd.run(client),
            Self::Ecdsa(cmd) => cmd.run(client),
            Self::Ek(cmd) => cmd.run(client),
            Self::Quote(cmd) => cmd.run(client),
            Self::Startup(cmd) => cmd.run(client),
        }
    }
}

#[derive(Parser, Debug)]
struct Opts {
    #[arg(long, default_value = "warn")]
    logging: LevelFilter,

    #[arg(long)]
    tcti: Option<String>,

    #[arg(long, default_value = "127.0.0.1:2321")]
    tpm_host: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:2322")]
    platform_host: SocketAddr,

    #[command(subcommand)]
    command: RootCommandHierarchy,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    env_logger::Builder::from_default_env()
        .format_target(true)
        .format_module_path(true)
        .filter(None, opts.logging)
        .try_init()?;

    let mut client = if let Some(tcti) = opts.tcti {
        TpmClient::connect_with_tcti(&tcti)?
    } else if std::env::var("TPM2TOOLS_TCTI").is_ok() {
        TpmClient::connect_from_env()?
    } else {
        TpmClient::connect(opts.tpm_host, opts.platform_host)?
    };

    opts.command.run(&mut client)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_random() {
        let opts = Opts::try_parse_from(["tpm_tool", "get-random", "32"]).unwrap();
        assert!(matches!(
            opts.command,
            RootCommandHierarchy::GetRandom(ref cmd) if cmd.n == 32
        ));
    }

    #[test]
    fn test_parse_hash_data() {
        let opts = Opts::try_parse_from(["tpm_tool", "hash", "--data", "hello world"]).unwrap();
        assert!(matches!(
            opts.command,
            RootCommandHierarchy::Hash(ref cmd) if cmd.data.as_deref() == Some("hello world")
        ));
    }

    #[test]
    fn test_parse_pcr_read_and_extend() {
        let read_opts = Opts::try_parse_from(["tpm_tool", "pcr", "read", "10"]).unwrap();
        assert!(matches!(
            read_opts.command,
            RootCommandHierarchy::Pcr(command::pcr::Pcr::Read(ref cmd)) if cmd.pcr == 10
        ));

        let extend_opts = Opts::try_parse_from([
            "tpm_tool",
            "pcr",
            "extend",
            "10",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();
        assert!(matches!(
            extend_opts.command,
            RootCommandHierarchy::Pcr(command::pcr::Pcr::Extend(ref cmd)) if cmd.pcr == 10
        ));
    }

    #[test]
    fn test_parse_ek_and_ecdsa() {
        let ek_opts =
            Opts::try_parse_from(["tpm_tool", "ek", "get", "--ecc", "nist-p256"]).unwrap();
        assert!(matches!(
            ek_opts.command,
            RootCommandHierarchy::Ek(command::ek::Ek::Get(_))
        ));

        let ecdsa_opts = Opts::try_parse_from(["tpm_tool", "ecdsa", "create"]).unwrap();
        assert!(matches!(
            ecdsa_opts.command,
            RootCommandHierarchy::Ecdsa(command::ecdsa::Ecdsa::Create(_))
        ));
    }

    #[test]
    fn test_parse_hash_conflict() {
        let res = Opts::try_parse_from(["tpm_tool", "hash", "input.bin", "--data", "hello"]);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_quote() {
        let opts = Opts::try_parse_from([
            "tpm_tool",
            "quote",
            "10",
            "--data",
            "nonce",
            "--ak-out",
            "ak.der",
            "--sig-out",
            "sig.bin",
        ])
        .unwrap();
        assert!(matches!(opts.command, RootCommandHierarchy::Quote(_)));
    }
}
