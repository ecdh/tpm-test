use crate::TpmDevice;
use anyhow::{anyhow, Context, Result};
use log::{error, info, warn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Multi-threaded MSSIM server that listens for TPM commands and Platform commands,
/// forwarding traffic to an underlying TpmDevice backend.
pub struct MssimServer {
    bind_addr: String,
    port: u16,
    device: Arc<Mutex<dyn TpmDevice>>,
}

impl MssimServer {
    pub fn new(bind_addr: &str, port: u16, mut device: Box<dyn TpmDevice>) -> Result<Self> {
        device
            .init()
            .context("Failed during TpmDevice initialization")?;
        Ok(Self {
            bind_addr: bind_addr.to_string(),
            port,
            device: Arc::new(Mutex::new(device)),
        })
    }

    pub fn from_arc(bind_addr: &str, port: u16, device: Arc<Mutex<dyn TpmDevice>>) -> Result<Self> {
        {
            let mut dev = device
                .lock()
                .map_err(|e| anyhow!("Failed to lock device: {e}"))?;
            dev.init()
                .context("Failed during TpmDevice initialization")?;
        }
        Ok(Self {
            bind_addr: bind_addr.to_string(),
            port,
            device,
        })
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn platform_port(&self) -> u16 {
        self.port + 1
    }

    /// Run the MSSIM server on the current thread, accepting incoming connections.
    pub fn run(self) -> Result<()> {
        let tpm_listener =
            TcpListener::bind((self.bind_addr.as_str(), self.port)).with_context(|| {
                format!(
                    "Failed to bind to TPM address {}:{}",
                    self.bind_addr, self.port
                )
            })?;
        let platform_listener = TcpListener::bind((self.bind_addr.as_str(), self.platform_port()))
            .with_context(|| {
                format!(
                    "Failed to bind to Platform address {}:{}",
                    self.bind_addr,
                    self.platform_port()
                )
            })?;

        info!(
            "MssimServer listening on {}:{} (TPM) and {}:{} (Platform)",
            self.bind_addr,
            self.port,
            self.bind_addr,
            self.platform_port()
        );

        let device_tpm = self.device.clone();
        thread::spawn(move || {
            for stream in tpm_listener.incoming() {
                match stream {
                    Ok(s) => {
                        let dev = device_tpm.clone();
                        thread::spawn(move || {
                            if let Err(e) = handle_local_tpm_client(s, dev) {
                                error!("Error handling TPM client: {:?}", e);
                            }
                        });
                    }
                    Err(e) => error!("Error accepting TPM connection: {}", e),
                }
            }
        });

        let device_platform = self.device.clone();
        for stream in platform_listener.incoming() {
            match stream {
                Ok(s) => {
                    let dev = device_platform.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_local_platform_client(s, dev) {
                            error!("Error handling Platform client: {:?}", e);
                        }
                    });
                }
                Err(e) => error!("Error accepting Platform connection: {}", e),
            }
        }

        Ok(())
    }
}

impl Drop for MssimServer {
    fn drop(&mut self) {
        if let Ok(mut dev) = self.device.lock() {
            let _ = dev.shutdown();
        }
    }
}

impl MssimServer {
    pub fn run_tcp_tunnel(bind_addr: &str, port: u16, tpm_host: String) -> Result<()> {
        let (ip, port_str) = tpm_host
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid tpm_host: expected host:port, got '{}'", tpm_host))?;
        let backend_port = port_str.parse::<u16>()?;

        let tpm_backend_addr = format!("{}:{}", ip, backend_port);
        let platform_backend_addr = format!("{}:{}", ip, backend_port + 1);

        let tpm_listener = TcpListener::bind((bind_addr, port)).with_context(|| {
            format!(
                "Failed to bind to TPM tunnel address {}:{}",
                bind_addr, port
            )
        })?;
        let platform_listener = TcpListener::bind((bind_addr, port + 1)).with_context(|| {
            format!(
                "Failed to bind to Platform tunnel address {}:{}",
                bind_addr,
                port + 1
            )
        })?;

        info!(
            "TCP Tunnel listening on {}:{} (TPM) and {}:{} (Platform), forwarding to {}",
            bind_addr,
            port,
            bind_addr,
            port + 1,
            tpm_backend_addr
        );

        let tpm_backend_clone = tpm_backend_addr.clone();
        thread::spawn(move || {
            for stream in tpm_listener.incoming() {
                match stream {
                    Ok(s) => {
                        let addr = tpm_backend_clone.clone();
                        thread::spawn(move || handle_tcp_tunnel_stream(s, addr));
                    }
                    Err(e) => error!("Error accepting TPM connection: {}", e),
                }
            }
        });

        for stream in platform_listener.incoming() {
            match stream {
                Ok(s) => {
                    let addr = platform_backend_addr.clone();
                    thread::spawn(move || handle_tcp_tunnel_stream(s, addr));
                }
                Err(e) => error!("Error accepting Platform connection: {}", e),
            }
        }

        Ok(())
    }
}

fn handle_local_tpm_client(mut stream: TcpStream, device: Arc<Mutex<dyn TpmDevice>>) -> Result<()> {
    info!("New client connected to TPM command port");
    loop {
        let mut cmd_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut cmd_buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                info!("Client disconnected from TPM command port");
                break;
            }
            return Err(e).context("Failed to read command ID");
        }
        let cmd = u32::from_be_bytes(cmd_buf);
        match cmd {
            8 => {
                // TPM_SEND_COMMAND
                let mut locality = [0u8; 1];
                stream
                    .read_exact(&mut locality)
                    .context("Failed to read locality")?;
                let mut size_buf = [0u8; 4];
                stream
                    .read_exact(&mut size_buf)
                    .context("Failed to read command size")?;
                let size = u32::from_be_bytes(size_buf) as usize;

                const MAX_TPM_COMMAND_SIZE: usize = 65536;
                if size > MAX_TPM_COMMAND_SIZE {
                    return Err(anyhow!(
                        "Command size {} exceeds maximum allowable ({})",
                        size,
                        MAX_TPM_COMMAND_SIZE
                    ));
                }

                let mut cmd_bytes = vec![0u8; size];
                stream
                    .read_exact(&mut cmd_bytes)
                    .context("Failed to read command bytes")?;

                let mut res_buf = vec![0u8; 65536];
                let res_size = {
                    let mut dev = device
                        .lock()
                        .map_err(|e| anyhow!("Device lock poisoned: {e}"))?;
                    dev.transmit(&cmd_bytes).context("Device transmit failed")?;
                    dev.receive(&mut res_buf).context("Device receive failed")?
                };

                // Send back: [size (4 bytes)] [res_bytes] [ack (4 bytes, 0)]
                stream
                    .write_all(&(res_size as u32).to_be_bytes())
                    .context("Failed to write response size")?;
                stream
                    .write_all(&res_buf[..res_size])
                    .context("Failed to write response bytes")?;
                stream
                    .write_all(&0u32.to_be_bytes())
                    .context("Failed to write ack")?;
                stream.flush().context("Failed to flush response")?;
            }
            9 => {
                // TPM_SESSION_END
                info!("Client sent TPM_SESSION_END");
                break;
            }
            _ => {
                warn!("Unsupported mssim command: {}", cmd);
                return Err(anyhow!("Unsupported mssim command: {}", cmd));
            }
        }
    }
    Ok(())
}

fn handle_local_platform_client(
    mut stream: TcpStream,
    device: Arc<Mutex<dyn TpmDevice>>,
) -> Result<()> {
    info!("New client connected to Platform port");
    loop {
        let mut cmd_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut cmd_buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                info!("Platform client disconnected");
                break;
            }
            return Err(e).context("Failed to read platform command");
        }
        let cmd = u32::from_be_bytes(cmd_buf);
        info!("Received platform command: {}", cmd);

        let ack = {
            let mut dev = device
                .lock()
                .map_err(|e| anyhow!("Platform client device lock poisoned: {e}"))?;
            match dev.handle_platform_command(cmd) {
                Ok(code) => code,
                Err(e) => {
                    warn!("Platform command {} error: {:?}", cmd, e);
                    1 // Non-zero indicates failure
                }
            }
        };

        stream
            .write_all(&ack.to_be_bytes())
            .context("Failed to write platform ack")?;
        stream.flush().context("Failed to flush platform ack")?;
    }
    Ok(())
}

fn handle_tcp_tunnel_stream(client: TcpStream, backend_addr: String) {
    info!("New TCP tunnel connection, forwarding to {}", backend_addr);
    let backend = match TcpStream::connect(&backend_addr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to backend {}: {}", backend_addr, e);
            return;
        }
    };

    let mut client_read = match client.try_clone() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to clone client stream: {}", e);
            return;
        }
    };
    let mut client_write = client;

    let mut backend_read = match backend.try_clone() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to clone backend stream: {}", e);
            return;
        }
    };
    let mut backend_write = backend;

    let t1 = thread::spawn(move || {
        if let Err(e) = std::io::copy(&mut client_read, &mut backend_write) {
            warn!("Error copying client to backend: {}", e);
        }
        let _ = backend_write.shutdown(std::net::Shutdown::Write);
    });

    let t2 = thread::spawn(move || {
        if let Err(e) = std::io::copy(&mut backend_read, &mut client_write) {
            warn!("Error copying backend to client: {}", e);
        }
        let _ = client_write.shutdown(std::net::Shutdown::Write);
    });

    let _ = t1.join();
    let _ = t2.join();
    info!("TCP tunnel connection closed");
}
