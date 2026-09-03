use crate::{ensure_buffer_capacity, TpmDevice, TpmHeader, TPM_HEADER_SIZE};
use anyhow::{Context, Result};
use log::info;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Device backend that interacts directly with a Linux TPM character device (/dev/tpmrm0 or /dev/tpm0).
pub struct LinuxDevice {
    file: File,
    path: String,
}

impl LinuxDevice {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        info!("Opening Linux TPM device at {}", path_str);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("Failed to open TPM device file {}", path_str))?;
        Ok(Self {
            file,
            path: path_str,
        })
    }
}

impl TpmDevice for LinuxDevice {
    fn transmit(&mut self, command: &[u8]) -> Result<()> {
        let header = TpmHeader::validate_frame(command)?;
        info!(
            "Transmitting {} bytes (tag={:04x}, code={:08x}) to Linux TPM ({})",
            command.len(),
            header.tag,
            header.code,
            self.path
        );
        self.file
            .write_all(command)
            .with_context(|| format!("Failed to write to TPM device {}", self.path))?;
        self.file.flush()?;
        Ok(())
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize> {
        info!("Reading response from Linux TPM ({})", self.path);
        ensure_buffer_capacity(response, TPM_HEADER_SIZE)?;
        let bytes_read = self
            .file
            .read(response)
            .with_context(|| format!("Failed to read from TPM device {}", self.path))?;
        if bytes_read > 0 {
            let _ = TpmHeader::validate_frame(&response[..bytes_read])?;
        }
        info!("Read {} bytes from Linux TPM", bytes_read);
        Ok(bytes_read)
    }

    fn handle_platform_command(&mut self, command: u32) -> Result<u32> {
        info!("Linux TPM: Received platform command {} (no-op)", command);
        Ok(0)
    }
}
