pub extern crate anyhow;
pub extern crate clap;
pub extern crate env_logger;
pub extern crate log;
use anyhow::{anyhow, Result};

pub mod devices;
pub mod server;

pub use devices::{DynamicTctiDevice, LinuxDevice, MockDevice, UnixSocketDevice};
pub use server::MssimServer;

/// Standard TPM 2.0 wire header size in bytes: [tag: 2B] [size: 4B] [code: 4B].
pub const TPM_HEADER_SIZE: usize = 10;

/// Checks that a buffer has at least the required capacity.
pub fn ensure_buffer_capacity(buf: &[u8], required: usize) -> Result<()> {
    if buf.len() < required {
        return Err(anyhow!(
            "Buffer capacity too small: needed {} bytes, got {}",
            required,
            buf.len()
        ));
    }
    Ok(())
}

/// Standard TPM 2.0 command and response wire header.
///
/// Every standard TPM 2.0 command and response frame starts with a 10-byte header:
/// - `tag`: `TPMI_ST_COMMAND_TAG` (for commands) or `TPM_ST` (for responses)
/// - `size`: Total frame size in bytes including this header
/// - `code`: `TPM_CC` (command code) or `TPM_RC` (response code)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmHeader {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

impl TpmHeader {
    /// Parses and validates a TPM 2.0 10-byte header from the beginning of a buffer.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        ensure_buffer_capacity(buf, TPM_HEADER_SIZE)?;
        let tag = u16::from_be_bytes([buf[0], buf[1]]);
        let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let code = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        if (size as usize) < TPM_HEADER_SIZE {
            return Err(anyhow!(
                "Invalid TPM 2.0 header size: {} bytes (expected at least {})",
                size,
                TPM_HEADER_SIZE
            ));
        }
        Ok(Self { tag, size, code })
    }

    /// Validates that a buffer contains a complete TPM 2.0 frame matching its declared header size.
    pub fn validate_frame(buf: &[u8]) -> Result<Self> {
        let header = Self::parse(buf)?;
        let expected = header.size as usize;
        if buf.len() < expected {
            return Err(anyhow!(
                "Incomplete TPM 2.0 frame: buffer has {} bytes, but header declared {}",
                buf.len(),
                expected
            ));
        }
        Ok(header)
    }
}


/// Pluggable trait for TPM device backends.
///
/// Any TPM implementation (in-process mock, Linux /dev/tpmrm0,
/// Unix domain socket, or custom hardware dev board) can implement
/// this trait to be proxied over MSSIM TCP.
pub trait TpmDevice: Send + 'static {
    /// Transmits a raw TPM 2.0 command byte buffer to the device.
    fn transmit(&mut self, command: &[u8]) -> Result<()>;

    /// Receives a raw TPM 2.0 response byte buffer from the device.
    /// Returns the number of bytes written to `response`.
    fn receive(&mut self, response: &mut [u8]) -> Result<usize>;

    /// Handles an MSSIM platform command (e.g. 1=PowerOn, 2=PowerOff, 17=Reset).
    /// Returns the 4-byte platform acknowledgement code (0 for success).
    fn handle_platform_command(&mut self, _command: u32) -> Result<u32> {
        Ok(0)
    }

    /// Hardware/device initialization hook called automatically before serving traffic.
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    /// Hardware/device shutdown hook called automatically when server shuts down.
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<T: TpmDevice + ?Sized> TpmDevice for Box<T> {
    fn transmit(&mut self, command: &[u8]) -> Result<()> {
        (**self).transmit(command)
    }

    fn receive(&mut self, response: &mut [u8]) -> Result<usize> {
        (**self).receive(response)
    }

    fn handle_platform_command(&mut self, command: u32) -> Result<u32> {
        (**self).handle_platform_command(command)
    }

    fn init(&mut self) -> Result<()> {
        (**self).init()
    }

    fn shutdown(&mut self) -> Result<()> {
        (**self).shutdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn get_unique_temp_path(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("/tmp/{}_{}_{}", prefix, std::process::id(), nanos)
    }

    fn get_two_free_ports() -> (TcpListener, TcpListener, u16) {
        let mut port = 10000 + (std::process::id() % 40000) as u16;
        loop {
            if let Ok(l1) = TcpListener::bind(("127.0.0.1", port)) {
                if let Ok(l2) = TcpListener::bind(("127.0.0.1", port + 1)) {
                    return (l1, l2, port);
                }
            }
            port = (port + 2) % 65000 + 1024;
        }
    }

    #[test]
    fn test_mock_device_operations() -> Result<()> {
        let mut mock = MockDevice::new();

        // 1. Send Startup command (TPM2_CC_Startup = 0x00000144)
        let startup_cmd = [
            0x80, 0x01, // tag = TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0c, // size = 12
            0x00, 0x00, 0x01, 0x44, // code = TPM2_CC_Startup
            0x00, 0x00, // SU_CLEAR
        ];
        mock.transmit(&startup_cmd)?;
        let mut resp = vec![0u8; 64];
        let resp_len = mock.receive(&mut resp)?;
        assert_eq!(resp_len, 10);
        assert_eq!(&resp[6..10], &[0, 0, 0, 0]); // TPM_RC_SUCCESS
        assert!(mock.startup_called);

        // 2. Send GetRandom command (TPM2_CC_GetRandom = 0x0000017b, 8 bytes)
        let get_random_cmd = [
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x0c, // size = 12
            0x00, 0x00, 0x01, 0x7b, // code = TPM2_CC_GetRandom
            0x00, 0x08, // bytes_requested = 8
        ];
        mock.transmit(&get_random_cmd)?;
        let resp_len = mock.receive(&mut resp)?;
        assert_eq!(resp_len, 12 + 8);
        assert_eq!(&resp[6..10], &[0, 0, 0, 0]); // TPM_RC_SUCCESS
        assert_eq!(&resp[10..12], &[0, 8]); // size = 8
        assert_eq!(&resp[12..20], &[0xA5; 8]); // Dummy pattern

        // 3. Platform command
        let ack = mock.handle_platform_command(17)?;
        assert_eq!(ack, 0);

        // 4. Send Hash command (TPM2_CC_Hash = 0x0000017d, 22 bytes total)
        let hash_cmd = [
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x16, // size = 22
            0x00, 0x00, 0x01, 0x7d, // code = TPM2_CC_Hash
            0x00, 0x04, b't', b'e', b's', b't', // data buffer (2 bytes size + 4 bytes data)
            0x00, 0x0b, // hashAlg = SHA256 (0x000b)
            0x40, 0x00, 0x00, 0x07, // hierarchy = TPM_RH_NULL
        ];
        mock.transmit(&hash_cmd)?;
        let resp_len = mock.receive(&mut resp)?;
        assert_eq!(resp_len, 52);
        assert_eq!(&resp[0..2], &[0x80, 0x01]); // TPM_ST_NO_SESSIONS
        assert_eq!(&resp[2..6], &[0, 0, 0, 52]); // response size = 52
        assert_eq!(&resp[6..10], &[0, 0, 0, 0]); // TPM_RC_SUCCESS
        assert_eq!(&resp[10..12], &[0, 32]); // digest size = 32
        assert_eq!(&resp[12..44], &[0xBB; 32]); // Dummy pattern
        assert_eq!(&resp[44..46], &[0x80, 0x24]); // TPM_ST_HASHCHECK
        assert_eq!(&resp[46..50], &[0x40, 0x00, 0x00, 0x07]); // TPM_RH_NULL
        assert_eq!(&resp[50..52], &[0, 0]); // validation digest size = 0

        Ok(())
    }

    #[test]
    fn test_unix_socket_device_transmit_receive() -> Result<()> {
        let sock_path = get_unique_temp_path("test_tpm_unix_socket");
        let listener = UnixListener::bind(&sock_path)?;

        let server_thread = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut cmd_buf = [0u8; 12];
            stream.read_exact(&mut cmd_buf)?;
            // Verify received command tag and code
            assert_eq!(cmd_buf[0..2], [0x80, 0x01]);
            assert_eq!(cmd_buf[6..10], [0x00, 0x00, 0x01, 0x44]);

            // Reply with TPM_RC_SUCCESS response (10 bytes: tag=8001, size=10, rc=0)
            let response = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
            stream.write_all(&response)?;
            stream.flush()?;
            Ok(())
        });

        let mut device = UnixSocketDevice::connect(&sock_path)?;

        let startup_cmd = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        device.transmit(&startup_cmd)?;

        let mut resp_buf = vec![0u8; 64];
        let bytes_received = device.receive(&mut resp_buf)?;
        assert_eq!(bytes_received, 10);
        assert_eq!(
            &resp_buf[..10],
            &[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );

        server_thread.join().unwrap()?;
        let _ = fs::remove_file(&sock_path);
        Ok(())
    }

    #[test]
    fn test_linux_device_file_io() -> Result<()> {
        let temp_file_path = get_unique_temp_path("test_tpm_dev_file");
        // Create an empty temporary file
        fs::File::create(&temp_file_path)?;

        let mut linux_dev = LinuxDevice::open(&temp_file_path)?;
        let startup_cmd = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        linux_dev.transmit(&startup_cmd)?;

        // Verify the bytes written by LinuxDevice to the file
        let written_bytes = fs::read(&temp_file_path)?;
        assert_eq!(written_bytes, startup_cmd);

        // Overwrite the file with a mock TPM response to test receive()
        let mock_resp = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
        fs::write(&temp_file_path, &mock_resp)?;

        // Re-open device to read from start of file
        let mut linux_dev_read = LinuxDevice::open(&temp_file_path)?;
        let mut resp_buf = vec![0u8; 64];
        let bytes_read = linux_dev_read.receive(&mut resp_buf)?;
        assert_eq!(bytes_read, 10);
        assert_eq!(&resp_buf[..10], &mock_resp);

        let ack = linux_dev.handle_platform_command(1)?;
        assert_eq!(ack, 0);

        let _ = fs::remove_file(&temp_file_path);
        Ok(())
    }

    #[test]
    fn test_dynamic_tcti_device_error_handling() {
        // Test that an invalid TCTI configuration fails safely with an error
        let result = DynamicTctiDevice::new("non_existent_mock_tcti_12345");
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("Failed to initialize TCTI"));
    }

    #[test]
    fn test_dynamic_tcti_device_with_mock_mssim() -> Result<()> {
        let (tpm_listener, platform_listener, port) = get_two_free_ports();

        // Platform server thread to respond to mssim handshake
        let p_thread = thread::spawn(move || {
            if let Ok((mut stream, _)) = platform_listener.accept() {
                let mut cmd = [0u8; 4];
                while stream.read_exact(&mut cmd).is_ok() {
                    let _ = stream.write_all(&0u32.to_be_bytes());
                    let _ = stream.flush();
                }
            }
        });

        let server_thread = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = tpm_listener.accept()?;
            let mut cmd_id = [0u8; 4];
            stream.read_exact(&mut cmd_id)?;
            assert_eq!(u32::from_be_bytes(cmd_id), 8); // TPM_SEND_COMMAND

            let mut locality = [0u8; 1];
            stream.read_exact(&mut locality)?;

            let mut size_buf = [0u8; 4];
            stream.read_exact(&mut size_buf)?;
            let size = u32::from_be_bytes(size_buf) as usize;

            let mut cmd_payload = vec![0u8; size];
            stream.read_exact(&mut cmd_payload)?;
            assert_eq!(cmd_payload[0..2], [0x80, 0x01]);

            // Reply: [size=10 (4B)] [payload: 10B] [ack=0 (4B)]
            let resp_payload = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
            stream.write_all(&10u32.to_be_bytes())?;
            stream.write_all(&resp_payload)?;
            stream.write_all(&0u32.to_be_bytes())?;
            stream.flush()?;
            Ok(())
        });

        // Initialize DynamicTctiDevice with mssim TCTI pointing to our mock server
        let tcti_conf = format!("mssim:host=127.0.0.1,port={}", port);
        let mut dev = DynamicTctiDevice::new(&tcti_conf)?;

        let startup_cmd = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        dev.transmit(&startup_cmd)?;

        let mut resp_buf = vec![0u8; 64];
        let bytes_received = dev.receive(&mut resp_buf)?;
        assert_eq!(bytes_received, 10);
        assert_eq!(
            &resp_buf[..10],
            &[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );

        drop(dev); // Tests Tss2_TctiLdr_Finalize
        server_thread.join().unwrap()?;
        let _ = p_thread.join();
        Ok(())
    }

    #[test]
    fn test_tpm_header_parse_and_validate() -> Result<()> {
        // Valid 12-byte command: tag=0x8001, size=12, code=0x00000144
        let cmd = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let header = TpmHeader::parse(&cmd)?;
        assert_eq!(header.tag, 0x8001);
        assert_eq!(header.size, 12);
        assert_eq!(header.code, 0x00000144);
        let validated = TpmHeader::validate_frame(&cmd)?;
        assert_eq!(validated, header);

        // Valid 10-byte response: tag=0x8001, size=10, rc=0
        let resp = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
        let resp_header = TpmHeader::parse(&resp)?;
        assert_eq!(resp_header.tag, 0x8001);
        assert_eq!(resp_header.size, 10);
        assert_eq!(resp_header.code, 0);
        let resp_validated = TpmHeader::validate_frame(&resp)?;
        assert_eq!(resp_validated, resp_header);

        // Too short for header (< 10 bytes)
        assert!(TpmHeader::parse(&[0x80, 0x01, 0x00, 0x00]).is_err());

        // Header size declared < 10
        let invalid_size_header = [0x80, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        assert!(TpmHeader::parse(&invalid_size_header).is_err());

        // Incomplete frame (buffer shorter than declared size in header)
        let incomplete = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x44,
        ];
        assert!(TpmHeader::parse(&incomplete).is_ok());
        assert!(TpmHeader::validate_frame(&incomplete).is_err());

        Ok(())
    }

    #[test]
    fn test_ensure_buffer_capacity() {
        let buf = [0u8; 16];
        assert!(ensure_buffer_capacity(&buf, 10).is_ok());
        assert!(ensure_buffer_capacity(&buf, 16).is_ok());
        assert!(ensure_buffer_capacity(&buf, 17).is_err());
    }
}
