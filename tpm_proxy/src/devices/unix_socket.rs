use crate::{ensure_buffer_capacity, TpmDevice, TpmHeader, TPM_HEADER_SIZE};
use anyhow::{Context, Result};
use log::info;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Device backend that forwards raw TPM 2.0 frames over a Unix domain socket.
pub struct UnixSocketDevice {
    stream: UnixStream,
    path: String,
}

impl UnixSocketDevice {
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        info!("Connecting to TPM Unix domain socket at {}", path_str);
        let stream = UnixStream::connect(&path)
            .with_context(|| format!("Failed to connect to Unix socket {}", path_str))?;
        Ok(Self {
            stream,
            path: path_str,
        })
    }
}

impl TpmDevice for UnixSocketDevice {
    fn transmit(&mut self, command: &[u8]) -> Result<()> {
        let header = TpmHeader::validate_frame(command)?;
        info!(
            "Transmitting {} bytes (tag={:04x}, code={:08x}) to Unix socket ({})",
            command.len(),
            header.tag,
            header.code,
            self.path
        );
        self.stream
            .write_all(command)
            .with_context(|| format!("Failed to write to Unix socket {}", self.path))?;
        self.stream.flush()?;
        Ok(())
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize> {
        info!("Reading TPM response from Unix socket ({})", self.path);
        ensure_buffer_capacity(response, TPM_HEADER_SIZE)?;

        // Read 10-byte standard TPM 2.0 header: [tag: 2B] [size: 4B] [code: 4B]
        self.stream
            .read_exact(&mut response[..TPM_HEADER_SIZE])
            .context("Failed to read TPM response header from Unix socket")?;

        let header = TpmHeader::parse(&response[..TPM_HEADER_SIZE])?;
        let size = header.size as usize;
        ensure_buffer_capacity(response, size)?;

        if size > TPM_HEADER_SIZE {
            self.stream
                .read_exact(&mut response[TPM_HEADER_SIZE..size])
                .context("Failed to read TPM response payload from Unix socket")?;
        }

        info!("Successfully received {} bytes from Unix socket", size);
        Ok(size)
    }

    fn handle_platform_command(&mut self, command: u32) -> Result<u32> {
        info!(
            "Unix socket TPM: Received platform command {} (no-op)",
            command
        );
        Ok(0)
    }
}
