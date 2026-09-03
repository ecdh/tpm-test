use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use log::info;
use tpm_proxy_lib::devices::{DynamicTctiDevice, LinuxDevice, MockDevice, UnixSocketDevice};
use tpm_proxy_lib::MssimServer;

#[derive(Parser, Debug)]
#[command(
    name = "tpm_proxy",
    author,
    version,
    about = "MSSIM TCP Proxy for TPM 2.0 Devices"
)]
struct Args {
    /// Device type to proxy to
    #[arg(short, long, value_enum)]
    device_type: DeviceType,

    /// Port to listen on for TPM commands (Platform commands will be on port + 1)
    #[arg(short, long, default_value_t = 2321)]
    port: u16,

    /// IP address to bind to
    #[arg(short, long, default_value = "127.0.0.1")]
    bind_addr: String,

    /// TPM host address (IP:port) for TCP device type
    #[arg(short, long, required_if_eq("device_type", "tcp"))]
    tpm_host: Option<String>,

    /// Linux character device path (e.g. /dev/tpmrm0 or /dev/tpm0)
    #[arg(long, default_value = "/dev/tpmrm0")]
    dev_path: String,

    /// Unix domain socket path for unix-socket device type
    #[arg(long, required_if_eq("device_type", "unix-socket"))]
    socket_path: Option<String>,

    /// TCTI configuration string for dynamic-tcti / usb (e.g. 'usb', 'device:/dev/tpm0', or path to .so)
    #[arg(long, default_value = "usb")]
    tcti_conf: String,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
enum DeviceType {
    /// TCP forwarding to an external TPM simulator
    Tcp,
    /// Direct Linux TPM character device (/dev/tpmrm0, /dev/tpm0)
    LinuxDev,
    /// Dynamic C-ABI TCTI loader via tss2-tctildr
    DynamicTcti,
    /// USB TPM device (alias for dynamic-tcti with 'usb' config)
    Usb,
    /// Unix domain socket bridge
    UnixSocket,
    /// In-memory mock TPM for testing
    Mock,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    info!("Starting TPM Proxy with args: {:?}", args);

    match args.device_type {
        DeviceType::Tcp => {
            let tpm_host = args
                .tpm_host
                .ok_or_else(|| anyhow!("--tpm-host is required for tcp device type"))?;
            MssimServer::run_tcp_tunnel(&args.bind_addr, args.port, tpm_host)?;
        }
        DeviceType::LinuxDev => {
            let dev = LinuxDevice::open(&args.dev_path)?;
            let server = MssimServer::new(&args.bind_addr, args.port, Box::new(dev))?;
            server.run()?;
        }
        DeviceType::DynamicTcti | DeviceType::Usb => {
            let config = if args.device_type == DeviceType::Usb {
                "usb"
            } else {
                &args.tcti_conf
            };
            let dev = DynamicTctiDevice::new(config)?;
            let server = MssimServer::new(&args.bind_addr, args.port, Box::new(dev))?;
            server.run()?;
        }
        DeviceType::UnixSocket => {
            let socket_path = args
                .socket_path
                .ok_or_else(|| anyhow!("--socket-path is required for unix-socket device type"))?;
            let dev = UnixSocketDevice::connect(&socket_path)?;
            let server = MssimServer::new(&args.bind_addr, args.port, Box::new(dev))?;
            server.run()?;
        }
        DeviceType::Mock => {
            let dev = MockDevice::new();
            let server = MssimServer::new(&args.bind_addr, args.port, Box::new(dev))?;
            server.run()?;
        }
    }

    Ok(())
}
