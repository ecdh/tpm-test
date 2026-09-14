use log::info;
use tpm_test_support::{tpm_test, TpmClient};

#[tpm_test(
    categories = "Compliance | Smoke",
    hierarchies = "Null",
    description = "Sends TPM2_Startup(SU_CLEAR) to verify basic power-on and initialization"
)]
fn test_startup() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    info!("Sending TPM Startup(SU_CLEAR)...");
    client.startup_clear().expect("startup clear");

    info!("Startup successful!");
}

