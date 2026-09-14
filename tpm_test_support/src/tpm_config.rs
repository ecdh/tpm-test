use anyhow::Result;
use std::collections::HashSet;
use tss_esapi::constants::{AlgorithmIdentifier, CapabilityType, CommandCode, PropertyTag};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::CapabilityData;

/// Represents dynamic TPM runtime capabilities, buffer limits, and supported algorithms.
///
/// Discovered dynamically at runtime via `TPM2_GetCapability` and `TPM2_GetProperty`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmConfig {
    /// Maximum digest size (in bytes) across all supported hash algorithms.
    pub max_digest_size: usize,
    /// Minimum digest size (in bytes) across all supported hash algorithms.
    pub min_digest_size: usize,
    /// The hash algorithm producing the largest digest size.
    pub largest_hash_alg: Option<HashingAlgorithm>,
    /// The hash algorithm producing the smallest digest size.
    pub shortest_hash_alg: Option<HashingAlgorithm>,
    /// Maximum command input buffer size (TPM_PT_INPUT_BUFFER).
    pub max_input_buffer: usize,
    /// Maximum NV index allocation size (TPM_PT_NV_INDEX_MAX).
    pub max_nv_index_size: usize,
    /// Maximum bytes in a single NV read/write operation (TPM_PT_NV_BUFFER_MAX).
    pub max_nv_op_size: usize,
    /// Safe NV index size: `min(max_nv_index_size, max_nv_op_size)`.
    pub safe_nv_index_size: usize,
    /// Maximum qualification data size: `max_digest_size + 2`.
    pub max_qual_data_size: usize,
    /// Maximum ECC key size in bytes across all supported ECC curves.
    pub max_ecc_key_size: usize,
    /// Maximum label size: `min(32, min(max_ecc_key_size, max_digest_size))`.
    pub max_label_size: usize,
    /// Total number of PCRs (TPM_PT_PCR_COUNT).
    pub pcr_count: u32,
    /// FIPS 140-2 compliance flag (from TPM_PT_MODES).
    pub fips_mode: bool,
    /// Total implemented commands count (TPM_PT_TOTAL_COMMANDS).
    pub total_commands: u32,
    /// Implemented command codes discovered via `TPM_CAP_COMMANDS`.
    pub supported_commands: HashSet<CommandCode>,
    /// Implemented algorithm identifiers discovered via `TPM_CAP_ALGS`.
    pub implemented_algorithms: HashSet<AlgorithmIdentifier>,
    /// Implemented hash algorithms discovered via `TPM_CAP_ALGS`.
    pub hash_algorithms: Vec<HashingAlgorithm>,
    /// Implemented ECC curves discovered via `TPM_CAP_ECC_CURVES`.
    pub ecc_curves: Vec<EccCurve>,
}

impl TpmConfig {
    /// Returns the standard digest size in bytes for a hashing algorithm.
    pub fn digest_size(alg: HashingAlgorithm) -> usize {
        match alg {
            HashingAlgorithm::Sha1 => 20,
            HashingAlgorithm::Sha256 => 32,
            HashingAlgorithm::Sha384 => 48,
            HashingAlgorithm::Sha512 => 64,
            HashingAlgorithm::Sm3_256 => 32,
            HashingAlgorithm::Sha3_256 => 32,
            HashingAlgorithm::Sha3_384 => 48,
            HashingAlgorithm::Sha3_512 => 64,
            HashingAlgorithm::Null => 0,
        }
    }

    /// Returns the key size in bytes for a supported ECC curve.
    pub fn ecc_key_size(curve: EccCurve) -> usize {
        match curve {
            EccCurve::NistP192 => 24,
            EccCurve::NistP224 => 28,
            EccCurve::NistP256 => 32,
            EccCurve::NistP384 => 48,
            EccCurve::NistP521 => 66,
            EccCurve::BnP256 => 32,
            EccCurve::BnP638 => 80,
            EccCurve::Sm2P256 => 32,
        }
    }

    /// Checks if a command code is supported by the TPM.
    pub fn is_command_supported(&self, cmd: CommandCode) -> bool {
        self.supported_commands.contains(&cmd)
    }

    /// Checks if an algorithm identifier is supported by the TPM.
    pub fn is_algorithm_supported(&self, alg: AlgorithmIdentifier) -> bool {
        self.implemented_algorithms.contains(&alg)
    }

    /// Checks if a hash algorithm is supported by the TPM.
    pub fn is_hash_supported(&self, alg: HashingAlgorithm) -> bool {
        self.hash_algorithms.contains(&alg)
    }

    /// Checks if an ECC curve is supported by the TPM.
    pub fn is_ecc_curve_supported(&self, curve: EccCurve) -> bool {
        self.ecc_curves.contains(&curve)
    }

    /// Discovers TPM configuration and capabilities by querying the live TPM.
    pub fn discover(context: &mut tss_esapi::Context) -> Result<Self> {
        context.clear_sessions();

        // 1. Query TPM Properties
        let max_digest_prop = context
            .get_tpm_property(PropertyTag::MaxDigest)
            .ok()
            .flatten()
            .unwrap_or(32) as usize;
        let input_buffer = context
            .get_tpm_property(PropertyTag::InputBuffer)
            .ok()
            .flatten()
            .unwrap_or(1024) as usize;
        let nv_index_max = context
            .get_tpm_property(PropertyTag::NvIndexMax)
            .ok()
            .flatten()
            .unwrap_or(2048) as usize;
        let nv_buffer_max = context
            .get_tpm_property(PropertyTag::NvBufferMax)
            .ok()
            .flatten()
            .unwrap_or(max_digest_prop as u32) as usize;
        let pcr_count = context
            .get_tpm_property(PropertyTag::PcrCount)
            .ok()
            .flatten()
            .unwrap_or(24);
        let modes = context
            .get_tpm_property(PropertyTag::Modes)
            .ok()
            .flatten()
            .unwrap_or(0);
        let total_commands = context
            .get_tpm_property(PropertyTag::TotalCommands)
            .ok()
            .flatten()
            .unwrap_or(0);
        let fips_mode = (modes & 0x00000001) != 0;

        // 2. Query Supported Commands via TPM_CAP_COMMANDS
        let mut supported_commands = HashSet::new();
        let mut cmd_property = 0x0000011Fu32;
        loop {
            let (cap_data, more_data) =
                match context.get_capability(CapabilityType::Command, cmd_property, 32) {
                    Ok(res) => res,
                    Err(_) => break,
                };
            if let CapabilityData::Commands(cmd_list) = cap_data {
                if cmd_list.is_empty() {
                    break;
                }
                for cca in cmd_list.iter() {
                    let cc_raw = cca.command_index() as u32;
                    if let Ok(cc) = CommandCode::try_from(cc_raw) {
                        supported_commands.insert(cc);
                    }
                    cmd_property = cc_raw + 1;
                }
            } else {
                break;
            }
            if !more_data {
                break;
            }
        }

        // 3. Query Implemented Algorithms via TPM_CAP_ALGS
        let mut implemented_algorithms = HashSet::new();
        let mut hash_algorithms = Vec::new();
        let mut alg_property = 0u32;
        loop {
            let (cap_data, more_data) =
                match context.get_capability(CapabilityType::Algorithms, alg_property, 32) {
                    Ok(res) => res,
                    Err(_) => break,
                };
            if let CapabilityData::Algorithms(alg_list) = cap_data {
                if alg_list.is_empty() {
                    break;
                }
                let mut last_id = alg_property;
                for alg_prop in alg_list.iter() {
                    let id = alg_prop.algorithm_identifier();
                    implemented_algorithms.insert(id);
                    if let Ok(h) = HashingAlgorithm::try_from(id) {
                        if !hash_algorithms.contains(&h) {
                            hash_algorithms.push(h);
                        }
                    }
                    last_id = (id as u16) as u32;
                }
                alg_property = last_id + 1;
            } else {
                break;
            }
            if !more_data {
                break;
            }
        }

        // 4. Query Implemented ECC Curves via TPM_CAP_ECC_CURVES
        let mut ecc_curves = Vec::new();
        let mut max_ecc_key_size = 0usize;
        let mut curve_property = 0u32;
        loop {
            let (cap_data, more_data) =
                match context.get_capability(CapabilityType::EccCurves, curve_property, 32) {
                    Ok(res) => res,
                    Err(_) => break,
                };
            if let CapabilityData::EccCurves(curve_list) = cap_data {
                if curve_list.is_empty() {
                    break;
                }
                let mut last_curve = curve_property;
                for curve_id in curve_list.iter() {
                    let curve = EccCurve::from(*curve_id);
                    let key_size = Self::ecc_key_size(curve);
                    if key_size > max_ecc_key_size {
                        max_ecc_key_size = key_size;
                    }
                    if !ecc_curves.contains(&curve) {
                        ecc_curves.push(curve);
                    }
                    last_curve = (*curve_id as u16) as u32;
                }
                curve_property = last_curve + 1;
            } else {
                break;
            }
            if !more_data {
                break;
            }
        }

        // 5. Compute Digest Bounds
        let mut max_digest_size = 0usize;
        let mut min_digest_size = usize::MAX;
        let mut largest_hash_alg = None;
        let mut shortest_hash_alg = None;

        for &alg in &hash_algorithms {
            if alg == HashingAlgorithm::Null {
                continue;
            }
            let sz = Self::digest_size(alg);
            if sz >= max_digest_size {
                max_digest_size = sz;
                largest_hash_alg = Some(alg);
            }
            if sz <= min_digest_size {
                min_digest_size = sz;
                shortest_hash_alg = Some(alg);
            }
        }
        if max_digest_size == 0 {
            max_digest_size = if max_digest_prop > 0 {
                max_digest_prop
            } else {
                32
            };
            min_digest_size = max_digest_size;
        }

        let max_qual_data_size = max_digest_size + 2;
        let safe_nv_index_size = std::cmp::min(nv_index_max, nv_buffer_max);
        let max_label_size = std::cmp::min(
            32,
            std::cmp::min(
                if max_ecc_key_size > 0 {
                    max_ecc_key_size
                } else {
                    32
                },
                max_digest_size,
            ),
        );

        Ok(Self {
            max_digest_size,
            min_digest_size,
            largest_hash_alg,
            shortest_hash_alg,
            max_input_buffer: input_buffer,
            max_nv_index_size: nv_index_max,
            max_nv_op_size: nv_buffer_max,
            safe_nv_index_size,
            max_qual_data_size,
            max_ecc_key_size,
            max_label_size,
            pcr_count,
            fips_mode,
            total_commands,
            supported_commands,
            implemented_algorithms,
            hash_algorithms,
            ecc_curves,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_size_mappings() {
        assert_eq!(TpmConfig::digest_size(HashingAlgorithm::Sha1), 20);
        assert_eq!(TpmConfig::digest_size(HashingAlgorithm::Sha256), 32);
        assert_eq!(TpmConfig::digest_size(HashingAlgorithm::Sha384), 48);
        assert_eq!(TpmConfig::digest_size(HashingAlgorithm::Sha512), 64);
        assert_eq!(TpmConfig::digest_size(HashingAlgorithm::Sm3_256), 32);
        assert_eq!(TpmConfig::digest_size(HashingAlgorithm::Null), 0);
    }

    #[test]
    fn test_ecc_key_size_mappings() {
        assert_eq!(TpmConfig::ecc_key_size(EccCurve::NistP192), 24);
        assert_eq!(TpmConfig::ecc_key_size(EccCurve::NistP224), 28);
        assert_eq!(TpmConfig::ecc_key_size(EccCurve::NistP256), 32);
        assert_eq!(TpmConfig::ecc_key_size(EccCurve::NistP384), 48);
        assert_eq!(TpmConfig::ecc_key_size(EccCurve::NistP521), 66);
    }
}
