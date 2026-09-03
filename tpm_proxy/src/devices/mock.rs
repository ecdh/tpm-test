use crate::{ensure_buffer_capacity, TpmDevice, TpmHeader};
use anyhow::{anyhow, Result};
use log::{info, warn};

/// In-memory mock TPM device for unit tests and local proxy verification.
pub struct MockDevice {
    pub startup_called: bool,
    pub pending_response: Vec<u8>,
}

impl Default for MockDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDevice {
    pub fn new() -> Self {
        Self {
            startup_called: false,
            pending_response: Vec::new(),
        }
    }
}

impl TpmDevice for MockDevice {
    fn transmit(&mut self, command: &[u8]) -> Result<()> {
        let header = TpmHeader::validate_frame(command)?;

        info!(
            "Mock TPM received cmd: tag={:04x}, size={}, code={:08x}",
            header.tag, header.size, header.code
        );

        let response = match header.code {
            0x00000144 => {
                // TPM2_CC_Startup
                info!("Mock TPM: Handling TPM2_CC_Startup");
                self.startup_called = true;
                // Return TPM_RC_SUCCESS (tag=8001, size=10, rc=0)
                vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
            }
            0x0000017b => {
                // TPM2_CC_GetRandom
                info!("Mock TPM: Handling TPM2_CC_GetRandom");
                if command.len() < 12 {
                    // TPM_RC_INSUFFICIENT (tag=8001, size=10, rc=0x1e)
                    vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x1e]
                } else {
                    let bytes_requested = u16::from_be_bytes([command[10], command[11]]) as usize;
                    info!("Mock TPM: Requested {} random bytes", bytes_requested);

                    let mut res = vec![0x80, 0x01];
                    let res_size = 12 + bytes_requested;
                    res.extend(&(res_size as u32).to_be_bytes());
                    res.extend(&0u32.to_be_bytes()); // TPM_RC_SUCCESS
                    res.extend(&(bytes_requested as u16).to_be_bytes());
                    res.extend(vec![0xA5; bytes_requested]); // Dummy pattern
                    res
                }
            }
            0x0000017d => {
                // TPM2_CC_Hash
                info!("Mock TPM: Handling TPM2_CC_Hash");
                // tag = TPM_ST_NO_SESSIONS
                let mut res = vec![0x80, 0x01];
                // size = 52
                res.extend(&52u32.to_be_bytes());
                // rc = TPM_RC_SUCCESS
                res.extend(&0u32.to_be_bytes());
                // outHash: TPM2B_DIGEST (2-byte size = 32, followed by 32 dummy bytes)
                res.extend(&32u16.to_be_bytes());
                res.extend([0xBB; 32]);
                // validation: TPMT_TK_HASHCHECK (tag: TPM_ST_HASHCHECK 0x8024,
                // hierarchy: TPM_RH_NULL 0x40000007, digest size: 0)
                res.extend(&0x8024u16.to_be_bytes());
                res.extend(&0x40000007u32.to_be_bytes());
                res.extend(&0u16.to_be_bytes());
                res
            }
            _ => {
                warn!(
                    "Mock TPM: Unsupported command code {:08x}, returning TPM_RC_COMMAND_CODE",
                    header.code
                );
                // TPM_RC_COMMAND_CODE = 0x143
                let mut res = vec![0x80, 0x01];
                res.extend(&10u32.to_be_bytes());
                res.extend(&0x00000143u32.to_be_bytes());
                res
            }
        };

        self.pending_response = response;
        Ok(())
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize> {
        if self.pending_response.is_empty() {
            return Err(anyhow!("No pending response in Mock TPM"));
        }
        let size = self.pending_response.len();
        ensure_buffer_capacity(response, size)?;
        response[..size].copy_from_slice(&self.pending_response);
        self.pending_response.clear();
        Ok(size)
    }

    fn handle_platform_command(&mut self, command: u32) -> Result<u32> {
        info!("Mock TPM: Handled platform command {}", command);
        Ok(0)
    }
}
