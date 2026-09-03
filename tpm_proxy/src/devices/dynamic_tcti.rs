use crate::{ensure_buffer_capacity, TpmDevice, TpmHeader, TPM_HEADER_SIZE};
use anyhow::{anyhow, Result};
use log::info;

/// Device backend that loads any TCTI module dynamically using Tss2_TctiLdr_Initialize.
pub struct DynamicTctiDevice {
    tcti_context: *mut tss_esapi_sys::TSS2_TCTI_CONTEXT,
    config: String,
}

// Safety: We protect DynamicTctiDevice with a Mutex in the server loop.
unsafe impl Send for DynamicTctiDevice {}

impl DynamicTctiDevice {
    pub fn new(config: &str) -> Result<Self> {
        let mut tcti_context: *mut tss_esapi_sys::TSS2_TCTI_CONTEXT = std::ptr::null_mut();
        let config_cstr = std::ffi::CString::new(config)?;
        info!("Initializing TCTI loader with config: {}...", config);
        let rc = unsafe {
            tss_esapi_sys::Tss2_TctiLdr_Initialize(config_cstr.as_ptr(), &mut tcti_context)
        };
        if rc != 0 {
            return Err(anyhow!("Failed to initialize TCTI '{}': RC {}", config, rc));
        }
        info!("TCTI '{}' initialized successfully", config);
        Ok(Self {
            tcti_context,
            config: config.to_string(),
        })
    }
}

impl Drop for DynamicTctiDevice {
    fn drop(&mut self) {
        if !self.tcti_context.is_null() {
            info!("Finalizing TCTI context for '{}'...", self.config);
            unsafe {
                tss_esapi_sys::Tss2_TctiLdr_Finalize(&mut self.tcti_context);
            }
        }
    }
}

impl TpmDevice for DynamicTctiDevice {
    fn transmit(&mut self, command: &[u8]) -> Result<()> {
        let header = TpmHeader::validate_frame(command)?;
        let tcti_v2 = self.tcti_context as *mut tss_esapi_sys::TSS2_TCTI_CONTEXT_COMMON_V2;
        let transmit_fn = unsafe { (*tcti_v2).v1.transmit }
            .ok_or_else(|| anyhow!("TCTI transmit function is null"))?;

        info!(
            "Transmitting {} bytes (tag={:04x}, code={:08x}) to TCTI ({})",
            command.len(),
            header.tag,
            header.code,
            self.config
        );
        let rc = unsafe { transmit_fn(self.tcti_context, command.len() as _, command.as_ptr()) };
        if rc != 0 {
            return Err(anyhow!("TCTI transmit failed: RC {}", rc));
        }
        Ok(())
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize> {
        ensure_buffer_capacity(response, TPM_HEADER_SIZE)?;
        let tcti_v2 = self.tcti_context as *mut tss_esapi_sys::TSS2_TCTI_CONTEXT_COMMON_V2;
        let receive_fn = unsafe { (*tcti_v2).v1.receive }
            .ok_or_else(|| anyhow!("TCTI receive function is null"))?;

        let mut size = response.len() as _;
        info!("Waiting for response from TCTI ({})...", self.config);
        // Timeout -1 means block indefinitely
        let rc = unsafe { receive_fn(self.tcti_context, &mut size, response.as_mut_ptr(), -1) };
        if rc != 0 {
            return Err(anyhow!("TCTI receive failed: RC {}", rc));
        }
        let bytes_received = size as usize;
        if bytes_received > 0 {
            let _ = TpmHeader::validate_frame(&response[..bytes_received])?;
        }
        info!("Received {} bytes from TCTI ({})", bytes_received, self.config);
        Ok(bytes_received)
    }

    fn handle_platform_command(&mut self, command: u32) -> Result<u32> {
        info!(
            "TCTI ({}): Received platform command {} (no-op)",
            self.config, command
        );
        Ok(0)
    }
}
