use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::CommandCode;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::{AesKeyBits, CamelliaKeyBits, RsaKeyBits, Sm4KeyBits};
use tss_esapi::structures::SymmetricDefinitionObject;
use tss_esapi::Error as TssError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequirementLevel {
    Mandatory,
    Recommended,
    Optional,
    Deprecated,
    NotAllowed,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RequirementGroup<T> {
    #[serde(default)]
    pub mandatory: Vec<T>,
    #[serde(default)]
    pub recommended: Vec<T>,
    #[serde(default)]
    pub optional: Vec<T>,
    #[serde(default)]
    pub deprecated: Vec<T>,
    #[serde(default)]
    pub not_allowed: Vec<T>,
}

impl<T> RequirementGroup<T> {
    pub fn is_empty(&self) -> bool {
        self.mandatory.is_empty()
            && self.recommended.is_empty()
            && self.optional.is_empty()
            && self.deprecated.is_empty()
            && self.not_allowed.is_empty()
    }

    pub fn iter_with_levels(&self) -> impl Iterator<Item = (&T, RequirementLevel)> {
        self.mandatory
            .iter()
            .map(|x| (x, RequirementLevel::Mandatory))
            .chain(
                self.recommended
                    .iter()
                    .map(|x| (x, RequirementLevel::Recommended)),
            )
            .chain(
                self.optional
                    .iter()
                    .map(|x| (x, RequirementLevel::Optional)),
            )
            .chain(
                self.deprecated
                    .iter()
                    .map(|x| (x, RequirementLevel::Deprecated)),
            )
            .chain(
                self.not_allowed
                    .iter()
                    .map(|x| (x, RequirementLevel::NotAllowed)),
            )
    }
}

impl<T: std::fmt::Debug> RequirementGroup<T> {
    /// Evaluates `test_fn` across all 5 requirement tiers (`Mandatory`, `Recommended`,
    /// `Optional`, `Deprecated`, `NotAllowed`), logging per-item verdicts and returning an
    /// error if any compliance expectation is violated.
    pub fn evaluate<F, U>(&self, label: &str, mut test_fn: F, is_unsupported: U) -> Result<()>
    where
        F: FnMut(&T) -> Result<()>,
        U: Fn(&anyhow::Error) -> bool,
    {
        let mut failed = false;

        for (item, level) in self.iter_with_levels() {
            match level {
                RequirementLevel::Mandatory => {
                    log::info!("Running Mandatory test for {} {:?}", label, item);
                    if let Err(e) = test_fn(item) {
                        log::error!("FAIL: Mandatory {} {:?} failed: {:#}", label, item, e);
                        failed = true;
                    } else {
                        log::info!("PASS: Mandatory {} {:?} succeeded", label, item);
                    }
                }
                RequirementLevel::Recommended => {
                    log::info!("Running Recommended test for {} {:?}", label, item);
                    match test_fn(item) {
                        Ok(_) => log::info!("PASS: Recommended {} {:?} succeeded", label, item),
                        Err(e) if is_unsupported(&e) => {
                            log::warn!(
                                "WARNING: Recommended {} {:?} is not supported by TPM",
                                label,
                                item
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "FAIL: Recommended {} {:?} failed with unexpected error: {:#}",
                                label,
                                item,
                                e
                            );
                            failed = true;
                        }
                    }
                }
                RequirementLevel::Optional => {
                    log::info!("Running Optional test for {} {:?}", label, item);
                    match test_fn(item) {
                        Ok(_) => log::info!("Optional {} {:?} succeeded", label, item),
                        Err(e) if is_unsupported(&e) => {
                            log::info!(
                                "Optional {} {:?} is not supported - skipping",
                                label,
                                item
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "FAIL: Optional {} {:?} failed with unexpected error: {:#}",
                                label,
                                item,
                                e
                            );
                            failed = true;
                        }
                    }
                }
                RequirementLevel::Deprecated => {
                    log::info!("Running Deprecated test for {} {:?}", label, item);
                    match test_fn(item) {
                        Ok(_) => {
                            log::warn!(
                                "WARNING: Deprecated {} {:?} succeeded (supported by TPM)",
                                label,
                                item
                            );
                        }
                        Err(e) if is_unsupported(&e) => {
                            log::info!(
                                "Deprecated {} {:?} is not supported - skipping (good)",
                                label,
                                item
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "FAIL: Deprecated {} {:?} failed with unexpected error: {:#}",
                                label,
                                item,
                                e
                            );
                            failed = true;
                        }
                    }
                }
                RequirementLevel::NotAllowed => {
                    log::info!("Running NotAllowed test for {} {:?}", label, item);
                    match test_fn(item) {
                        Ok(_) => {
                            log::error!(
                                "FAIL: NotAllowed {} {:?} succeeded (supported by TPM)!",
                                label,
                                item
                            );
                            failed = true;
                        }
                        Err(e) if is_unsupported(&e) => {
                            log::info!(
                                "PASS: NotAllowed {} {:?} was rejected by TPM as unsupported",
                                label,
                                item
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "NotAllowed {} {:?} failed with non-unsupported error (treating as pass): {:#}",
                                label,
                                item,
                                e
                            );
                        }
                    }
                }
            }
        }

        if failed {
            anyhow::bail!("Some {} compliance checks failed", label);
        }
        Ok(())
    }
}

/// Checks whether a `tss_esapi` error indicates that a requested algorithm, curve, key size,
/// or mode is unsupported by the target TPM.
pub fn is_unsupported_algorithm_error(err: &anyhow::Error) -> bool {
    if let Some(TssError::Tss2Error(rc)) = err.downcast_ref::<TssError>() {
        return matches!(
            rc.kind(),
            Some(
                Tss2ResponseCodeKind::Asymmetric
                    | Tss2ResponseCodeKind::Attributes
                    | Tss2ResponseCodeKind::CommandCode
                    | Tss2ResponseCodeKind::Curve
                    | Tss2ResponseCodeKind::Hash
                    | Tss2ResponseCodeKind::Kdf
                    | Tss2ResponseCodeKind::KeySize
                    | Tss2ResponseCodeKind::Mgf
                    | Tss2ResponseCodeKind::Mode
                    | Tss2ResponseCodeKind::Scheme
                    | Tss2ResponseCodeKind::Symmetric
                    | Tss2ResponseCodeKind::Type
                    | Tss2ResponseCodeKind::Value
            )
        );
    }
    false
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct AsymmetricConfig {
    #[serde(default)]
    pub rsa_key_sizes: Option<RequirementGroup<u32>>,
    #[serde(default)]
    pub ecc_curves: Option<RequirementGroup<String>>,
    #[serde(default)]
    pub algorithms: Option<RequirementGroup<String>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct AlgorithmsConfig {
    #[serde(default)]
    pub hash: Option<RequirementGroup<String>>,
    #[serde(default)]
    pub asymmetric: Option<AsymmetricConfig>,
    #[serde(default)]
    pub symmetric: Option<RequirementGroup<String>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileConfig {
    pub profile_name: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub algorithms: Option<AlgorithmsConfig>,
    #[serde(default)]
    pub commands: Option<RequirementGroup<String>>,
}

#[derive(clap::Args, Debug, Clone, Default)]
pub struct ProfileArgs {
    /// Path to the profile config JSON file.
    #[arg(short = 'C', long, env = "TPM_PROFILE_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Comma-separated list of mandatory items.
    #[arg(short = 'M', long, value_delimiter = ',')]
    pub mandatory: Vec<String>,

    /// Comma-separated list of recommended items.
    #[arg(short = 'R', long, value_delimiter = ',')]
    pub recommended: Vec<String>,

    /// Comma-separated list of optional items.
    #[arg(short = 'O', long, value_delimiter = ',')]
    pub optional: Vec<String>,

    /// Comma-separated list of deprecated items.
    #[arg(short = 'D', long, value_delimiter = ',')]
    pub deprecated: Vec<String>,

    /// Comma-separated list of not-allowed items.
    #[arg(short = 'N', long, value_delimiter = ',')]
    pub not_allowed: Vec<String>,
}

#[derive(clap::Parser, Debug, Clone, Default)]
#[command(author, version, about, long_about = None)]
pub struct ProfileCli {
    #[command(flatten)]
    pub profile: ProfileArgs,
}

/// Meta group containing all domain-specific requirement maps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainMaps {
    pub hash_algorithms: HashMap<String, RequirementLevel>,
    pub ecc_curves: HashMap<String, RequirementLevel>,
    pub rsa_key_sizes: HashMap<u32, RequirementLevel>,
    pub asymmetric_schemes: HashMap<String, RequirementLevel>,
    pub symmetric_ciphers: HashMap<String, RequirementLevel>,
    pub commands: HashMap<String, RequirementLevel>,
}

pub fn canonical_command_name(name: &str) -> String {
    if let Some(code) = parse_command_code(name) {
        return format!("TPM2_CC_{:?}", code).to_uppercase();
    }
    let upper = name.trim().to_uppercase().replace('-', "_");
    if let Some(stripped) = upper.strip_prefix("TPM2_CC_") {
        format!("TPM2_CC_{}", stripped)
    } else if let Some(stripped) = upper.strip_prefix("CC_") {
        format!("TPM2_CC_{}", stripped)
    } else if let Some(stripped) = upper.strip_prefix("TPM_CC_") {
        format!("TPM2_CC_{}", stripped)
    } else {
        format!("TPM2_CC_{}", upper)
    }
}

fn insert_string_group(
    map: &mut HashMap<String, RequirementLevel>,
    group: &RequirementGroup<String>,
) {
    for (item, level) in group.iter_with_levels() {
        map.insert(item.trim().to_lowercase().replace('-', "_"), level);
    }
}

fn insert_command_group(
    map: &mut HashMap<String, RequirementLevel>,
    group: &RequirementGroup<String>,
) {
    for (item, level) in group.iter_with_levels() {
        map.insert(canonical_command_name(item), level);
    }
}

fn insert_rsa_group(map: &mut HashMap<u32, RequirementLevel>, group: &RequirementGroup<u32>) {
    for (&size, level) in group.iter_with_levels() {
        map.insert(size, level);
    }
}

fn is_hash_algorithm(name: &str) -> bool {
    let key = name.trim().to_lowercase().replace('-', "_");
    parse_hashing_algorithm(&key).is_some()
        || matches!(key.as_str(), "sha224" | "sha512_224" | "sha512_256")
}

fn is_ecc_curve(name: &str) -> bool {
    let key = name.trim().to_lowercase().replace('-', "_");
    parse_ecc_curve(&key).is_some() || matches!(key.as_str(), "curve25519" | "ed25519")
}

fn is_asymmetric_scheme(name: &str) -> bool {
    let key = name.trim().to_lowercase().replace('-', "_");
    matches!(
        key.as_str(),
        "rsassa"
            | "rsapss"
            | "rsaes"
            | "oaep"
            | "ecdsa"
            | "ecdh"
            | "ecdaa"
            | "ec_ephemeral"
            | "mldsa87"
            | "mlkem768"
            | "mldsa"
            | "mlkem"
    )
}

fn is_symmetric_cipher(name: &str) -> bool {
    let key = name.trim().to_lowercase().replace('-', "_");
    key.starts_with("aes")
        || key.starts_with("sm4")
        || key.starts_with("camellia")
        || key.starts_with("tdes")
}

impl DomainMaps {
    /// Routes a CLI override item to the appropriate domain map.
    pub fn apply_override(&mut self, raw_name: &str, status: RequirementLevel) {
        let name = raw_name.trim();
        let key = name.to_lowercase().replace('-', "_");
        let upper_key = name.to_uppercase().replace('-', "_");

        // 1. Numeric RSA key size (e.g. "2048")
        if let Ok(size) = name.parse::<u32>() {
            self.rsa_key_sizes.insert(size, status);
            return;
        }

        // 2. Prefixed RSA key size (e.g. "rsa2048")
        if let Some(stripped) = key.strip_prefix("rsa") {
            if let Ok(size) = stripped.parse::<u32>() {
                self.rsa_key_sizes.insert(size, status);
                return;
            }
        }

        // 3. TPM2_CC command
        if parse_command_code(name).is_some()
            || upper_key.starts_with("TPM2_CC_")
            || upper_key.starts_with("CC_")
            || upper_key.starts_with("TPM_CC_")
            || self.commands.contains_key(&canonical_command_name(name))
        {
            let canonical = canonical_command_name(name);
            self.commands.insert(canonical, status);
            return;
        }

        // 4. Update existing map if already present from JSON5
        if self.hash_algorithms.contains_key(&key) {
            self.hash_algorithms.insert(key, status);
        } else if self.ecc_curves.contains_key(&key) {
            self.ecc_curves.insert(key, status);
        } else if self.asymmetric_schemes.contains_key(&key) {
            self.asymmetric_schemes.insert(key, status);
        } else if self.symmetric_ciphers.contains_key(&key) {
            self.symmetric_ciphers.insert(key, status);
        }
        // 5. Categorize based on typed parsers and domain checks
        else if parse_hashing_algorithm(&key).is_some() || is_hash_algorithm(&key) {
            self.hash_algorithms.insert(key, status);
        } else if parse_ecc_curve(&key).is_some() || is_ecc_curve(&key) {
            self.ecc_curves.insert(key, status);
        } else if parse_symmetric_definition_object(&key).is_some() || is_symmetric_cipher(&key) {
            self.symmetric_ciphers.insert(key, status);
        } else if is_asymmetric_scheme(&key) {
            self.asymmetric_schemes.insert(key, status);
        } else {
            self.hash_algorithms.insert(key, status);
        }
    }

    pub fn get_status(&self, name: &str) -> Option<RequirementLevel> {
        let key = name.trim().to_lowercase().replace('-', "_");
        if let Ok(size) = key.parse::<u32>() {
            if let Some(status) = self.rsa_key_sizes.get(&size).copied() {
                return Some(status);
            }
        }
        if let Some(stripped) = key.strip_prefix("rsa") {
            if let Ok(size) = stripped.parse::<u32>() {
                if let Some(status) = self.rsa_key_sizes.get(&size).copied() {
                    return Some(status);
                }
            }
        }
        self.hash_algorithms
            .get(&key)
            .copied()
            .or_else(|| self.ecc_curves.get(&key).copied())
            .or_else(|| self.asymmetric_schemes.get(&key).copied())
            .or_else(|| self.symmetric_ciphers.get(&key).copied())
            .or_else(|| self.get_command_status(name))
    }

    pub fn get_hash_status(&self, alg: &str) -> Option<RequirementLevel> {
        self.hash_algorithms.get(&alg.to_lowercase()).copied()
    }

    pub fn get_ecc_curve_status(&self, curve: &str) -> Option<RequirementLevel> {
        self.ecc_curves.get(&curve.to_lowercase()).copied()
    }

    pub fn get_rsa_key_size_status(&self, size: u32) -> Option<RequirementLevel> {
        self.rsa_key_sizes
            .get(&size)
            .copied()
            .or_else(|| self.get_status(&format!("rsa{}", size)))
            .or_else(|| self.get_status(&size.to_string()))
    }

    pub fn get_asymmetric_scheme_status(&self, scheme: &str) -> Option<RequirementLevel> {
        self.asymmetric_schemes.get(&scheme.to_lowercase()).copied()
    }

    pub fn get_symmetric_status(&self, cipher: &str) -> Option<RequirementLevel> {
        self.symmetric_ciphers.get(&cipher.to_lowercase()).copied()
    }

    pub fn get_command_status(&self, cmd: &str) -> Option<RequirementLevel> {
        let canonical = canonical_command_name(cmd);
        if let Some(status) = self.commands.get(&canonical).copied() {
            return Some(status);
        }
        if let Some(code) = parse_command_code(cmd) {
            let key = format!("TPM2_CC_{:?}", code).to_uppercase();
            if let Some(status) = self.commands.get(&key).copied() {
                return Some(status);
            }
        }
        let upper = cmd.trim().to_uppercase().replace('-', "_");
        self.commands.get(&upper).copied()
    }

    pub fn get_hash_algorithms_by_status(&self, status: RequirementLevel) -> Vec<String> {
        keys_by_status(&self.hash_algorithms, status)
    }

    pub fn get_ecc_curves_by_status(&self, status: RequirementLevel) -> Vec<String> {
        keys_by_status(&self.ecc_curves, status)
    }

    pub fn get_rsa_key_sizes_by_status(&self, status: RequirementLevel) -> Vec<u32> {
        keys_by_status(&self.rsa_key_sizes, status)
    }

    pub fn get_symmetric_ciphers_by_status(&self, status: RequirementLevel) -> Vec<String> {
        keys_by_status(&self.symmetric_ciphers, status)
    }

    pub fn get_commands_by_status(&self, status: RequirementLevel) -> Vec<String> {
        keys_by_status(&self.commands, status)
    }
}

fn keys_by_status<K: Clone + Ord>(map: &HashMap<K, RequirementLevel>, status: RequirementLevel) -> Vec<K> {
    let mut list: Vec<K> = map
        .iter()
        .filter(|(_, &s)| s == status)
        .map(|(k, _)| k.clone())
        .collect();
    list.sort();
    list
}

#[derive(Debug, Clone, Default)]
pub struct Profile {
    profile_name: Option<String>,
    domains: DomainMaps,
    has_config: bool,
}

impl Profile {
    /// Loads a profile from process arguments or environment variables (`TPM_PROFILE_CONFIG`).
    pub fn from_env() -> Result<Self> {
        let mut cli = ProfileCli::try_parse().unwrap_or_default();
        if cli.profile.config.is_none() {
            if let Ok(env_path) = std::env::var("TPM_PROFILE_CONFIG") {
                let trimmed = env_path.trim();
                if !trimmed.is_empty() {
                    cli.profile.config = Some(std::path::PathBuf::from(trimmed));
                }
            }
        }
        Self::load_from_profile_args(&cli.profile)
    }

    /// Loads a profile directly from a JSON5 configuration string.
    pub fn from_json5_str(content: &str) -> Result<Self> {
        let config: ProfileConfig =
            serde_json5::from_str(content).context("Failed to parse config JSON5 from string")?;
        let mut profile = Self::load_from_config(&config);
        profile.has_config = true;
        Ok(profile)
    }

    /// Builds a Profile from a parsed ProfileConfig.
    pub fn load_from_config(config: &ProfileConfig) -> Self {
        let mut domains = DomainMaps::default();
        let profile_name = config.profile_name.clone();

        // 1. Parse structured algorithms block if present
        if let Some(ref algs) = config.algorithms {
            if let Some(ref hash_group) = algs.hash {
                insert_string_group(&mut domains.hash_algorithms, hash_group);
            }
            if let Some(ref asym) = algs.asymmetric {
                if let Some(ref rsa_group) = asym.rsa_key_sizes {
                    insert_rsa_group(&mut domains.rsa_key_sizes, rsa_group);
                }
                if let Some(ref ecc_group) = asym.ecc_curves {
                    insert_string_group(&mut domains.ecc_curves, ecc_group);
                }
                if let Some(ref asym_group) = asym.algorithms {
                    insert_string_group(&mut domains.asymmetric_schemes, asym_group);
                }
            }
            if let Some(ref sym_group) = algs.symmetric {
                insert_string_group(&mut domains.symmetric_ciphers, sym_group);
            }
        }

        // 2. Parse commands block if present
        if let Some(ref cmd_group) = config.commands {
            insert_command_group(&mut domains.commands, cmd_group);
        }

        Profile {
            profile_name,
            domains,
            has_config: false,
        }
    }

    pub fn load_from_profile_args(args: &ProfileArgs) -> Result<Self> {
        let mut profile = if let Some(ref path) = args.config {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;
            let mut p = Self::from_json5_str(&content)
                .with_context(|| format!("Failed to parse config JSON5: {}", path.display()))?;
            p.has_config = true;
            p
        } else {
            Profile::default()
        };

        for (overrides, level) in [
            (&args.mandatory, RequirementLevel::Mandatory),
            (&args.recommended, RequirementLevel::Recommended),
            (&args.optional, RequirementLevel::Optional),
            (&args.deprecated, RequirementLevel::Deprecated),
            (&args.not_allowed, RequirementLevel::NotAllowed),
        ] {
            for alg in overrides {
                profile.domains.apply_override(alg, level);
            }
        }

        Ok(profile)
    }

    pub fn profile_name(&self) -> Option<&str> {
        self.profile_name.as_deref()
    }

    pub fn has_config(&self) -> bool {
        self.has_config
    }

    pub fn domains(&self) -> &DomainMaps {
        &self.domains
    }

    /// Generic requirement level lookup checking across hashes, curves, asymmetric schemes, and symmetric ciphers.
    pub fn get_status(&self, alg: &str) -> Option<RequirementLevel> {
        self.domains.get_status(alg)
    }

    /// Dedicated lookup for hash algorithm requirement level.
    pub fn get_hash_status(&self, alg: &str) -> Option<RequirementLevel> {
        self.domains.get_hash_status(alg)
    }

    /// Dedicated lookup for ECC curve requirement level.
    pub fn get_ecc_curve_status(&self, curve: &str) -> Option<RequirementLevel> {
        self.domains.get_ecc_curve_status(curve)
    }

    /// Dedicated lookup for RSA key size requirement level.
    pub fn get_rsa_key_size_status(&self, size: u32) -> Option<RequirementLevel> {
        self.domains.get_rsa_key_size_status(size)
    }

    /// Dedicated lookup for asymmetric signing/encryption scheme requirement level.
    pub fn get_asymmetric_scheme_status(&self, scheme: &str) -> Option<RequirementLevel> {
        self.domains.get_asymmetric_scheme_status(scheme)
    }

    /// Dedicated lookup for symmetric cipher requirement level.
    pub fn get_symmetric_status(&self, cipher: &str) -> Option<RequirementLevel> {
        self.domains.get_symmetric_status(cipher)
    }

    /// Dedicated lookup for TPM2_CC command requirement level.
    pub fn get_command_status(&self, cmd: &str) -> Option<RequirementLevel> {
        self.domains.get_command_status(cmd)
    }

    // Domain-specific query helpers
    pub fn get_hash_algorithms_by_status(&self, status: RequirementLevel) -> Vec<String> {
        self.domains.get_hash_algorithms_by_status(status)
    }

    pub fn get_ecc_curves_by_status(&self, status: RequirementLevel) -> Vec<String> {
        self.domains.get_ecc_curves_by_status(status)
    }

    pub fn get_rsa_key_sizes_by_status(&self, status: RequirementLevel) -> Vec<u32> {
        self.domains.get_rsa_key_sizes_by_status(status)
    }

    pub fn get_symmetric_ciphers_by_status(&self, status: RequirementLevel) -> Vec<String> {
        self.domains.get_symmetric_ciphers_by_status(status)
    }

    pub fn get_commands_by_status(&self, status: RequirementLevel) -> Vec<String> {
        self.domains.get_commands_by_status(status)
    }

    fn parse_dedup<I, T: PartialEq>(items: Vec<I>, parser: impl FnMut(I) -> Option<T>) -> Vec<T> {
        let mut list: Vec<T> = items.into_iter().filter_map(parser).collect();
        list.dedup();
        list
    }

    fn build_requirements<T: Clone>(
        &self,
        getter: impl Fn(&Self, RequirementLevel) -> Vec<T>,
        default_mandatory: &[T],
    ) -> RequirementGroup<T> {
        let mut group = RequirementGroup {
            mandatory: getter(self, RequirementLevel::Mandatory),
            recommended: getter(self, RequirementLevel::Recommended),
            optional: getter(self, RequirementLevel::Optional),
            deprecated: getter(self, RequirementLevel::Deprecated),
            not_allowed: getter(self, RequirementLevel::NotAllowed),
        };
        if group.is_empty() && !self.has_config() {
            group.mandatory = default_mandatory.to_vec();
        }
        group
    }

    /// Returns typed `HashingAlgorithm` items configured for a given requirement level.
    pub fn get_hashes(&self, status: RequirementLevel) -> Vec<HashingAlgorithm> {
        Self::parse_dedup(self.get_hash_algorithms_by_status(status), |name| {
            parse_hashing_algorithm(&name)
        })
    }

    /// Returns typed `EccCurve` items configured for a given requirement level.
    pub fn get_ecc_curves(&self, status: RequirementLevel) -> Vec<EccCurve> {
        Self::parse_dedup(self.get_ecc_curves_by_status(status), |name| {
            parse_ecc_curve(&name)
        })
    }

    /// Returns typed `RsaKeyBits` items configured for a given requirement level.
    pub fn get_rsa_key_bits(&self, status: RequirementLevel) -> Vec<RsaKeyBits> {
        Self::parse_dedup(self.get_rsa_key_sizes_by_status(status), parse_rsa_key_bits)
    }

    /// Returns typed `SymmetricDefinitionObject` items configured for a given requirement level.
    pub fn get_symmetric_ciphers(
        &self,
        status: RequirementLevel,
    ) -> Vec<SymmetricDefinitionObject> {
        Self::parse_dedup(self.get_symmetric_ciphers_by_status(status), |name| {
            parse_symmetric_definition_object(&name)
        })
    }

    /// Returns typed `CommandCode` items configured for a given requirement level.
    pub fn get_commands(&self, status: RequirementLevel) -> Vec<CommandCode> {
        Self::parse_dedup(self.get_commands_by_status(status), |name| {
            parse_command_code(&name)
        })
    }

    /// Returns the resolved requirements for hashing algorithms, applying `default_mandatory`
    /// if no profile config or explicit overrides were provided.
    pub fn hash_requirements(
        &self,
        default_mandatory: &[HashingAlgorithm],
    ) -> RequirementGroup<HashingAlgorithm> {
        self.build_requirements(Self::get_hashes, default_mandatory)
    }

    /// Returns the resolved requirements for ECC curves, applying `default_mandatory`
    /// if no profile config or explicit overrides were provided.
    pub fn ecc_curve_requirements(
        &self,
        default_mandatory: &[EccCurve],
    ) -> RequirementGroup<EccCurve> {
        self.build_requirements(Self::get_ecc_curves, default_mandatory)
    }

    /// Returns the resolved requirements for RSA key sizes, applying `default_mandatory`
    /// if no profile config or explicit overrides were provided.
    pub fn rsa_key_requirements(
        &self,
        default_mandatory: &[RsaKeyBits],
    ) -> RequirementGroup<RsaKeyBits> {
        self.build_requirements(Self::get_rsa_key_bits, default_mandatory)
    }

    /// Returns the resolved requirements for symmetric ciphers, applying `default_mandatory`
    /// if no profile config or explicit overrides were provided.
    pub fn symmetric_cipher_requirements(
        &self,
        default_mandatory: &[SymmetricDefinitionObject],
    ) -> RequirementGroup<SymmetricDefinitionObject> {
        self.build_requirements(Self::get_symmetric_ciphers, default_mandatory)
    }

    /// Returns the resolved requirements for command codes, applying `default_mandatory`
    /// if no profile config or explicit overrides were provided.
    pub fn command_requirements(
        &self,
        default_mandatory: &[CommandCode],
    ) -> RequirementGroup<CommandCode> {
        self.build_requirements(Self::get_commands, default_mandatory)
    }
}

/// Parses a hash algorithm name string (case-insensitive) into a `tss_esapi::interface_types::algorithm::HashingAlgorithm`.
pub fn parse_hashing_algorithm(name: &str) -> Option<HashingAlgorithm> {
    match name.trim().to_lowercase().as_str() {
        "sha256" | "sha-256" | "sha2_256" => Some(HashingAlgorithm::Sha256),
        "sha384" | "sha-384" | "sha2_384" => Some(HashingAlgorithm::Sha384),
        "sha512" | "sha-512" | "sha2_512" => Some(HashingAlgorithm::Sha512),
        "sha1" | "sha-1" => Some(HashingAlgorithm::Sha1),
        "sm3_256" | "sm3" => Some(HashingAlgorithm::Sm3_256),
        "sha3_256" | "sha3-256" => Some(HashingAlgorithm::Sha3_256),
        "sha3_384" | "sha3-384" => Some(HashingAlgorithm::Sha3_384),
        "sha3_512" | "sha3-512" => Some(HashingAlgorithm::Sha3_512),
        _ => None,
    }
}

/// Parses an ECC curve name string (case-insensitive) into a `tss_esapi::interface_types::ecc::EccCurve`.
pub fn parse_ecc_curve(name: &str) -> Option<EccCurve> {
    match name.trim().to_lowercase().as_str() {
        "nist_p256" | "nist-p256" | "p256" | "p-256" => Some(EccCurve::NistP256),
        "nist_p384" | "nist-p384" | "p384" | "p-384" => Some(EccCurve::NistP384),
        "nist_p521" | "nist-p521" | "p521" | "p-521" => Some(EccCurve::NistP521),
        "nist_p192" | "nist-p192" | "p192" | "p-192" => Some(EccCurve::NistP192),
        "nist_p224" | "nist-p224" | "p224" | "p-224" => Some(EccCurve::NistP224),
        "sm2_p256" | "sm2" | "sm2-p256" | "sm2p256" => Some(EccCurve::Sm2P256),
        "bn256" | "bn-256" | "bnp256" => Some(EccCurve::BnP256),
        "bn638" | "bn-638" | "bnp638" => Some(EccCurve::BnP638),
        _ => None,
    }
}

/// Parses an RSA key size (e.g. 1024, 2048, 3072, 4096) into a `tss_esapi::interface_types::key_bits::RsaKeyBits`.
pub fn parse_rsa_key_bits(size: u32) -> Option<RsaKeyBits> {
    match size {
        1024 => Some(RsaKeyBits::Rsa1024),
        2048 => Some(RsaKeyBits::Rsa2048),
        3072 => Some(RsaKeyBits::Rsa3072),
        4096 => Some(RsaKeyBits::Rsa4096),
        _ => None,
    }
}

/// Parses a symmetric cipher name string (case-insensitive) into a `tss_esapi::structures::SymmetricDefinitionObject`.
pub fn parse_symmetric_definition_object(name: &str) -> Option<SymmetricDefinitionObject> {
    let normalized = name.trim().to_lowercase().replace('-', "_");
    if normalized == "null" || normalized == "none" {
        return Some(SymmetricDefinitionObject::Null);
    }

    // Identify algorithm family
    let (family, mut rem) = if let Some(stripped) = normalized.strip_prefix("aes") {
        ("aes", stripped)
    } else if let Some(stripped) = normalized.strip_prefix("sm4") {
        ("sm4", stripped)
    } else if let Some(stripped) = normalized.strip_prefix("camellia") {
        ("camellia", stripped)
    } else {
        return None;
    };

    if rem.starts_with('_') {
        rem = &rem[1..];
    }

    // Extract key bits if present
    let (key_size, mut rem) = if let Some(stripped) = rem.strip_prefix("256") {
        (Some(256), stripped)
    } else if let Some(stripped) = rem.strip_prefix("192") {
        (Some(192), stripped)
    } else if let Some(stripped) = rem.strip_prefix("128") {
        (Some(128), stripped)
    } else {
        (None, rem)
    };

    if rem.starts_with('_') {
        rem = &rem[1..];
    }

    // Extract mode
    let mode = match rem {
        "" | "cfb" => SymmetricMode::Cfb,
        "cbc" => SymmetricMode::Cbc,
        "ctr" => SymmetricMode::Ctr,
        "ofb" => SymmetricMode::Ofb,
        "ecb" => SymmetricMode::Ecb,
        "null" => SymmetricMode::Null,
        _ => return None, // Reject unknown modes (e.g. gcm, ccm)
    };

    match family {
        "aes" => {
            let key_bits = match key_size {
                Some(256) => AesKeyBits::Aes256,
                Some(192) => AesKeyBits::Aes192,
                Some(128) | None => AesKeyBits::Aes128,
                _ => return None,
            };
            Some(SymmetricDefinitionObject::Aes { key_bits, mode })
        }
        "sm4" => {
            let key_bits = match key_size {
                Some(128) | None => Sm4KeyBits::Sm4_128,
                _ => return None,
            };
            Some(SymmetricDefinitionObject::Sm4 { key_bits, mode })
        }
        "camellia" => {
            let key_bits = match key_size {
                Some(256) => CamelliaKeyBits::Camellia256,
                Some(192) => CamelliaKeyBits::Camellia192,
                Some(128) | None => CamelliaKeyBits::Camellia128,
                _ => return None,
            };
            Some(SymmetricDefinitionObject::Camellia { key_bits, mode })
        }
        _ => None,
    }
}

/// Parses a command name string (e.g. `TPM2_CC_Startup`, `Startup`, `TPM2_CC_CreatePrimary`, `create_primary`, etc.)
/// into a `tss_esapi::constants::CommandCode`.
pub fn parse_command_code(name: &str) -> Option<CommandCode> {
    let mut normalized = name.trim().to_lowercase().replace('-', "_");
    if normalized.starts_with("tpm2_cc_") {
        normalized = normalized.trim_start_matches("tpm2_cc_").to_string();
    } else if normalized.starts_with("tpm_cc_") {
        normalized = normalized.trim_start_matches("tpm_cc_").to_string();
    } else if normalized.starts_with("cc_") {
        normalized = normalized.trim_start_matches("cc_").to_string();
    }
    let compact = normalized.replace('_', "");

    match compact.as_str() {
        "nvundefinespacespecial" => Some(CommandCode::NvUndefineSpaceSpecial),
        "evictcontrol" => Some(CommandCode::EvictControl),
        "hierarchycontrol" => Some(CommandCode::HierarchyControl),
        "nvundefinespace" => Some(CommandCode::NvUndefineSpace),
        "changeeps" => Some(CommandCode::ChangeEps),
        "changepps" => Some(CommandCode::ChangePps),
        "clear" => Some(CommandCode::Clear),
        "clearcontrol" => Some(CommandCode::ClearControl),
        "clockset" => Some(CommandCode::ClockSet),
        "hierarchychangeauth" => Some(CommandCode::HierarchyChangeAuth),
        "nvdefinespace" => Some(CommandCode::NvDefineSpace),
        "pcrallocate" => Some(CommandCode::PcrAllocate),
        "pcrsetauthpolicy" => Some(CommandCode::PcrSetAuthPolicy),
        "ppcommands" => Some(CommandCode::PpCommands),
        "setprimarypolicy" => Some(CommandCode::SetPrimaryPolicy),
        "fieldupgrade" | "fieldupgradestart" => Some(CommandCode::FieldUpgradeStart),
        "fieldupgradedata" => Some(CommandCode::FieldUpgradeData),
        "clockrateadjust" => Some(CommandCode::ClockRateAdjust),
        "createprimary" => Some(CommandCode::CreatePrimary),
        "nvglobalwritelock" => Some(CommandCode::NvGlobalWriteLock),
        "getcommandauditdigest" => Some(CommandCode::GetCommandAuditDigest),
        "nvincrement" => Some(CommandCode::NvIncrement),
        "nvsetbits" => Some(CommandCode::NvSetBits),
        "nvextend" => Some(CommandCode::NvExtend),
        "nvwrite" => Some(CommandCode::NvWrite),
        "nvwritelock" => Some(CommandCode::NvWriteLock),
        "dictionaryattacklockreset" => Some(CommandCode::DictionaryAttackLockReset),
        "dictionaryattackparameters" => Some(CommandCode::DictionaryAttackParameters),
        "nvchangeauth" => Some(CommandCode::NvChangeAuth),
        "pcrevent" => Some(CommandCode::PcrEvent),
        "pcrreset" => Some(CommandCode::PcrReset),
        "sequencecomplete" => Some(CommandCode::SequenceComplete),
        "setalgorithmset" => Some(CommandCode::SetAlgorithmSet),
        "setcommandcodeauditstatus" => Some(CommandCode::SetCommandCodeAuditStatus),
        "incrementalselftest" => Some(CommandCode::IncrementalSelfTest),
        "selftest" => Some(CommandCode::SelfTest),
        "startup" => Some(CommandCode::Startup),
        "shutdown" => Some(CommandCode::Shutdown),
        "stirrandom" => Some(CommandCode::StirRandom),
        "activatecredential" => Some(CommandCode::ActivateCredential),
        "certify" => Some(CommandCode::Certify),
        "policynv" => Some(CommandCode::PolicyNv),
        "certifycreation" => Some(CommandCode::CertifyCreation),
        "duplicate" => Some(CommandCode::Duplicate),
        "gettime" => Some(CommandCode::GetTime),
        "getsessionauditdigest" => Some(CommandCode::GetSessionAuditDigest),
        "nvread" => Some(CommandCode::NvRead),
        "nvreadlock" => Some(CommandCode::NvReadLock),
        "objectchangeauth" => Some(CommandCode::ObjectChangeAuth),
        "policysecret" => Some(CommandCode::PolicySecret),
        "rewrap" => Some(CommandCode::Rewrap),
        "create" => Some(CommandCode::Create),
        "ecdhzgen" => Some(CommandCode::EcdhZGen),
        "hmac" => Some(CommandCode::Hmac),
        "import" => Some(CommandCode::Import),
        "load" => Some(CommandCode::Load),
        "quote" => Some(CommandCode::Quote),
        "rsadecrypt" => Some(CommandCode::RsaDecrypt),
        "hmacstart" => Some(CommandCode::HmacStart),
        "sequenceupdate" => Some(CommandCode::SequenceUpdate),
        "sign" => Some(CommandCode::Sign),
        "unseal" => Some(CommandCode::Unseal),
        "policysigned" => Some(CommandCode::PolicySigned),
        "contextload" => Some(CommandCode::ContextLoad),
        "contextsave" => Some(CommandCode::ContextSave),
        "ecdhkeygen" => Some(CommandCode::EcdhKeyGen),
        "encryptdecrypt" => Some(CommandCode::EncryptDecrypt),
        "encryptdecrypt2" => Some(CommandCode::EncryptDecrypt2),
        "flushcontext" => Some(CommandCode::FlushContext),
        "loadexternal" => Some(CommandCode::LoadExternal),
        "makecredential" => Some(CommandCode::MakeCredential),
        "nvreadpublic" => Some(CommandCode::NvReadPublic),
        "policyauthorize" => Some(CommandCode::PolicyAuthorize),
        "policyauthvalue" => Some(CommandCode::PolicyAuthValue),
        "policycommandcode" => Some(CommandCode::PolicyCommandCode),
        "policycountertimer" => Some(CommandCode::PolicyCounterTimer),
        "policycphash" => Some(CommandCode::PolicyCpHash),
        "policylocality" => Some(CommandCode::PolicyLocality),
        "policynamehash" => Some(CommandCode::PolicyNameHash),
        "policyor" => Some(CommandCode::PolicyOr),
        "policyticket" => Some(CommandCode::PolicyTicket),
        "readpublic" => Some(CommandCode::ReadPublic),
        "rsaencrypt" => Some(CommandCode::RsaEncrypt),
        "startauthsession" => Some(CommandCode::StartAuthSession),
        "verifysignature" => Some(CommandCode::VerifySignature),
        "eccparameters" => Some(CommandCode::EccParameters),
        "firmwareread" => Some(CommandCode::FirmwareRead),
        "getcapability" => Some(CommandCode::GetCapability),
        "getrandom" => Some(CommandCode::GetRandom),
        "gettestresult" => Some(CommandCode::GetTestResult),
        "hash" => Some(CommandCode::Hash),
        "pcrread" => Some(CommandCode::PcrRead),
        "policypcr" => Some(CommandCode::PolicyPcr),
        "policyrestart" => Some(CommandCode::PolicyRestart),
        "readclock" => Some(CommandCode::ReadClock),
        "pcrextend" => Some(CommandCode::PcrExtend),
        "pcrsetauthvalue" => Some(CommandCode::PcrSetAuthValue),
        "nvcertify" => Some(CommandCode::NvCertify),
        "eventsequencecomplete" => Some(CommandCode::EventSequenceComplete),
        "hashsequencestart" => Some(CommandCode::HashSequenceStart),
        "policyphysicalpresence" => Some(CommandCode::PolicyPhysicalPresence),
        "policyduplicationselect" => Some(CommandCode::PolicyDuplicationSelect),
        "policygetdigest" => Some(CommandCode::PolicyGetDigest),
        "testparms" => Some(CommandCode::TestParms),
        "commit" => Some(CommandCode::Commit),
        "policypassword" => Some(CommandCode::PolicyPassword),
        "zgen2phase" => Some(CommandCode::ZGen2Phase),
        "ecephemeral" => Some(CommandCode::EcEphemeral),
        "policynvwritten" => Some(CommandCode::PolicyNvWritten),
        "policytemplate" => Some(CommandCode::PolicyTemplate),
        "createloaded" => Some(CommandCode::CreateLoaded),
        "policyauthorizenv" => Some(CommandCode::PolicyAuthorizeNv),
        "acgetcapability" => Some(CommandCode::AcGetCapability),
        "acsend" => Some(CommandCode::AcSend),
        "policyacsendselect" => Some(CommandCode::PolicyAcSendSelect),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_parsing_cli_overrides_routed_correctly() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct Cli {
            #[command(flatten)]
            profile: ProfileArgs,
        }

        let args = Cli::try_parse_from(&[
            "test_bin",
            "-M",
            "sha256,2048,nist_p256",
            "-R",
            "sha512,3072,nist_p384",
            "-O",
            "sm3_256,sm2,rsapss,aes128_cfb,TPM2_CC_Commit",
            "-D",
            "sha1,1024",
            "-N",
            "TPM2_CC_FieldUpgrade",
        ])
        .unwrap();

        let profile = Profile::load_from_profile_args(&args.profile).unwrap();

        // 1. Hashes
        assert_eq!(
            profile.get_hash_status("sha256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_hash_status("sha512"),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            profile.get_hash_status("sm3_256"),
            Some(RequirementLevel::Optional)
        );
        assert_eq!(
            profile.get_hash_status("sha1"),
            Some(RequirementLevel::Deprecated)
        );

        // 2. RSA key sizes
        assert_eq!(
            profile.get_rsa_key_size_status(2048),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_rsa_key_size_status(3072),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            profile.get_rsa_key_size_status(1024),
            Some(RequirementLevel::Deprecated)
        );

        // 3. ECC curves
        assert_eq!(
            profile.get_ecc_curve_status("nist_p256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_ecc_curve_status("nist_p384"),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            profile.get_ecc_curve_status("sm2"),
            Some(RequirementLevel::Optional)
        );

        // 4. Asymmetric schemes
        assert_eq!(
            profile.get_asymmetric_scheme_status("rsapss"),
            Some(RequirementLevel::Optional)
        );

        // 5. Symmetric ciphers
        assert_eq!(
            profile.get_symmetric_status("aes128_cfb"),
            Some(RequirementLevel::Optional)
        );

        // 6. Commands
        assert_eq!(
            profile.get_command_status("TPM2_CC_Commit"),
            Some(RequirementLevel::Optional)
        );
        assert_eq!(
            profile.get_command_status("TPM2_CC_FieldUpgrade"),
            Some(RequirementLevel::NotAllowed)
        );

        // 7. Verify NO cross-domain map pollution
        let mandatory_hashes = profile.get_hash_algorithms_by_status(RequirementLevel::Mandatory);
        assert_eq!(mandatory_hashes, vec!["sha256"]); // Does NOT contain "nist_p256" or "2048"!

        let mandatory_curves = profile.get_ecc_curves_by_status(RequirementLevel::Mandatory);
        assert_eq!(mandatory_curves, vec!["nist_p256"]); // Does NOT contain "sha256"!

        let mandatory_rsa = profile.get_rsa_key_sizes_by_status(RequirementLevel::Mandatory);
        assert_eq!(mandatory_rsa, vec![2048]);
    }

    #[test]
    fn test_structured_json5_dedicated_maps() {
        let json_content = r#"{
            profile_name: "Test_PC_Client_Profile",
            version: "2.0",
            algorithms: {
                hash: {
                    mandatory: ["sha256", "sha384"],
                    recommended: ["sha512"],
                    optional: ["sm3_256", "sha3_256"],
                    deprecated: [],
                    not_allowed: ["sha1"]
                },
                asymmetric: {
                    rsa_key_sizes: {
                        mandatory: [2048],
                        recommended: [3072],
                        optional: [4096],
                        not_allowed: [1024]
                    },
                    ecc_curves: {
                        mandatory: ["nist_p256"],
                        recommended: ["nist_p384"],
                        optional: ["sm2"]
                    },
                    algorithms: {
                        mandatory: ["rsassa", "ecdsa"],
                        optional: ["rsapss"]
                    }
                },
                symmetric: {
                    mandatory: ["aes128_cfb"],
                    optional: ["sm4_cfb"]
                }
            },
            commands: {
                mandatory: ["TPM2_CC_Startup", "TPM2_CC_Quote"],
                not_allowed: ["TPM2_CC_FieldUpgrade"]
            }
        }"#;

        let temp_path =
            std::env::temp_dir().join(format!("test_profile_{}.json5", std::process::id()));
        std::fs::write(&temp_path, json_content).unwrap();

        let profile_args = ProfileArgs {
            config: Some(temp_path.clone()),
            mandatory: vec![],
            recommended: vec![],
            optional: vec![],
            deprecated: vec![],
            not_allowed: vec![],
        };

        let profile = Profile::load_from_profile_args(&profile_args).unwrap();
        let _ = std::fs::remove_file(temp_path);

        assert_eq!(profile.profile_name(), Some("Test_PC_Client_Profile"));

        // Dedicated hash lookups
        assert_eq!(
            profile.get_hash_status("sha256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_hash_status("sha512"),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            profile.get_hash_status("sm3_256"),
            Some(RequirementLevel::Optional)
        );
        assert_eq!(
            profile.get_hash_status("sha1"),
            Some(RequirementLevel::NotAllowed)
        );

        // Dedicated ECC curve lookups
        assert_eq!(
            profile.get_ecc_curve_status("nist_p256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_ecc_curve_status("nist_p384"),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            profile.get_ecc_curve_status("sm2"),
            Some(RequirementLevel::Optional)
        );

        // Dedicated RSA key size lookups
        assert_eq!(
            profile.get_rsa_key_size_status(2048),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_rsa_key_size_status(3072),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            profile.get_rsa_key_size_status(4096),
            Some(RequirementLevel::Optional)
        );
        assert_eq!(
            profile.get_rsa_key_size_status(1024),
            Some(RequirementLevel::NotAllowed)
        );

        // Dedicated asymmetric scheme lookups
        assert_eq!(
            profile.get_asymmetric_scheme_status("rsassa"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_asymmetric_scheme_status("rsapss"),
            Some(RequirementLevel::Optional)
        );

        // Dedicated symmetric ciphers lookups
        assert_eq!(
            profile.get_symmetric_status("aes128_cfb"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_symmetric_status("sm4_cfb"),
            Some(RequirementLevel::Optional)
        );

        // Dedicated command lookups
        assert_eq!(
            profile.get_command_status("TPM2_CC_Startup"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_command_status("TPM2_CC_Quote"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_command_status("TPM2_CC_FieldUpgrade"),
            Some(RequirementLevel::NotAllowed)
        );
        assert_eq!(profile.get_command_status("TPM2_CC_PCR_Extend"), None);

        // Domain-specific lists
        let mandatory_hashes = profile.get_hash_algorithms_by_status(RequirementLevel::Mandatory);
        assert!(mandatory_hashes.contains(&"sha256".to_string()));
        assert!(mandatory_hashes.contains(&"sha384".to_string()));
        assert_eq!(mandatory_hashes.len(), 2);

        let typed_mandatory_hashes = profile.get_hashes(RequirementLevel::Mandatory);
        assert!(typed_mandatory_hashes.contains(&HashingAlgorithm::Sha256));
        assert!(typed_mandatory_hashes.contains(&HashingAlgorithm::Sha384));
        assert_eq!(typed_mandatory_hashes.len(), 2);

        let typed_mandatory_curves = profile.get_ecc_curves(RequirementLevel::Mandatory);
        assert_eq!(typed_mandatory_curves, vec![EccCurve::NistP256]);

        let typed_mandatory_rsa = profile.get_rsa_key_bits(RequirementLevel::Mandatory);
        assert_eq!(typed_mandatory_rsa, vec![RsaKeyBits::Rsa2048]);

        let typed_mandatory_sym = profile.get_symmetric_ciphers(RequirementLevel::Mandatory);
        assert_eq!(
            typed_mandatory_sym,
            vec![SymmetricDefinitionObject::AES_128_CFB]
        );

        // Test symmetric mode parsing combinations
        assert_eq!(
            parse_symmetric_definition_object("aes128_cbc"),
            Some(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cbc,
            })
        );
        assert_eq!(
            parse_symmetric_definition_object("aes-256-ctr"),
            Some(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes256,
                mode: SymmetricMode::Ctr,
            })
        );
        assert_eq!(
            parse_symmetric_definition_object("aes128_ofb"),
            Some(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Ofb,
            })
        );
        assert_eq!(
            parse_symmetric_definition_object("aes128_ecb"),
            Some(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Ecb,
            })
        );
        assert_eq!(
            parse_symmetric_definition_object("sm4_128_cbc"),
            Some(SymmetricDefinitionObject::Sm4 {
                key_bits: Sm4KeyBits::Sm4_128,
                mode: SymmetricMode::Cbc,
            })
        );
        assert_eq!(
            parse_symmetric_definition_object("camellia256_cbc"),
            Some(SymmetricDefinitionObject::Camellia {
                key_bits: CamelliaKeyBits::Camellia256,
                mode: SymmetricMode::Cbc,
            })
        );
        assert_eq!(
            parse_symmetric_definition_object("null"),
            Some(SymmetricDefinitionObject::Null)
        );

        let typed_mandatory_cmds = profile.get_commands(RequirementLevel::Mandatory);
        assert!(typed_mandatory_cmds.contains(&CommandCode::Startup));
        assert!(typed_mandatory_cmds.contains(&CommandCode::Quote));

        let typed_not_allowed_cmds = profile.get_commands(RequirementLevel::NotAllowed);
        assert_eq!(typed_not_allowed_cmds, vec![CommandCode::FieldUpgradeStart]);

        assert_eq!(
            parse_command_code("TPM2_CC_Startup"),
            Some(CommandCode::Startup)
        );
        assert_eq!(
            parse_command_code("create_primary"),
            Some(CommandCode::CreatePrimary)
        );
        assert_eq!(
            parse_command_code("pcr_extend"),
            Some(CommandCode::PcrExtend)
        );
        assert_eq!(
            parse_command_code("TPM2_CC_FieldUpgrade"),
            Some(CommandCode::FieldUpgradeStart)
        );
    }

    #[test]
    fn test_profile_from_json5_str() {
        let json_content = r#"{
            profile_name: "String_Loaded_Profile",
            algorithms: {
                hash: {
                    mandatory: ["sha256"],
                    optional: ["sha384"]
                },
                asymmetric: {
                    rsa_key_sizes: {
                        mandatory: [2048]
                    },
                    ecc_curves: {
                        mandatory: ["nist_p256"]
                    }
                }
            },
            commands: {
                mandatory: ["TPM2_CC_Startup"]
            }
        }"#;

        let profile = Profile::from_json5_str(json_content).unwrap();
        assert!(profile.has_config());
        assert_eq!(profile.profile_name(), Some("String_Loaded_Profile"));
        assert_eq!(
            profile.get_hash_status("sha256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_hash_status("sha384"),
            Some(RequirementLevel::Optional)
        );
        assert_eq!(
            profile.get_rsa_key_size_status(2048),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_ecc_curve_status("nist_p256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            profile.get_command_status("TPM2_CC_Startup"),
            Some(RequirementLevel::Mandatory)
        );
    }

    #[test]
    fn test_command_override_canonicalization() {
        let json_content = r#"{
            profile_name: "Override_Test_Profile",
            commands: {
                mandatory: ["TPM2_CC_Startup", "TPM2_CC_Quote"]
            }
        }"#;

        let temp_path =
            std::env::temp_dir().join(format!("test_override_{}.json5", std::process::id()));
        std::fs::write(&temp_path, json_content).unwrap();

        let profile_args = ProfileArgs {
            config: Some(temp_path.clone()),
            mandatory: vec![],
            recommended: vec![],
            optional: vec![],
            deprecated: vec![],
            not_allowed: vec!["startup".to_string()],
        };

        let profile = Profile::load_from_profile_args(&profile_args).unwrap();
        let _ = std::fs::remove_file(temp_path);

        // "startup" override should overwrite "TPM2_CC_Startup"
        assert_eq!(
            profile.get_command_status("TPM2_CC_Startup"),
            Some(RequirementLevel::NotAllowed)
        );
        assert_eq!(
            profile.get_command_status("startup"),
            Some(RequirementLevel::NotAllowed)
        );
        assert_eq!(
            profile.get_status("startup"),
            Some(RequirementLevel::NotAllowed)
        );
        assert_eq!(
            profile.get_status("TPM2_CC_Startup"),
            Some(RequirementLevel::NotAllowed)
        );
        assert_eq!(
            profile.get_command_status("TPM2_CC_Quote"),
            Some(RequirementLevel::Mandatory)
        );
    }

    #[test]
    fn test_from_env_fallback() {
        let json_content = r#"{
            profile_name: "Env_Fallback_Profile",
            algorithms: {
                hash: {
                    mandatory: ["sha256"]
                }
            }
        }"#;

        let temp_path =
            std::env::temp_dir().join(format!("test_env_fallback_{}.json5", std::process::id()));
        std::fs::write(&temp_path, json_content).unwrap();

        std::env::set_var("TPM_PROFILE_CONFIG", temp_path.to_str().unwrap());
        let profile = Profile::from_env().unwrap();
        std::env::remove_var("TPM_PROFILE_CONFIG");
        let _ = std::fs::remove_file(temp_path);

        assert!(profile.has_config());
        assert_eq!(profile.profile_name(), Some("Env_Fallback_Profile"));
        assert_eq!(
            profile.get_hash_status("sha256"),
            Some(RequirementLevel::Mandatory)
        );
    }

    #[test]
    fn test_strict_symmetric_cipher_parsing() {
        assert_eq!(parse_symmetric_definition_object("aes128_gcm"), None);
        assert_eq!(parse_symmetric_definition_object("aes_gcm"), None);
        assert_eq!(parse_symmetric_definition_object("aes128_xyz"), None);
        assert_eq!(parse_symmetric_definition_object("sm4_256"), None);
        assert_eq!(parse_symmetric_definition_object("sm4_gcm"), None);
        assert_eq!(parse_symmetric_definition_object("camellia_invalid"), None);
        assert_eq!(parse_symmetric_definition_object("des56_cbc"), None);
        assert_eq!(parse_symmetric_definition_object("unknown_cipher"), None);

        // Valid combinations
        assert!(parse_symmetric_definition_object("aes128").is_some());
        assert!(parse_symmetric_definition_object("aes-256-cfb").is_some());
        assert!(parse_symmetric_definition_object("sm4").is_some());
        assert!(parse_symmetric_definition_object("camellia128_cbc").is_some());
        assert!(parse_symmetric_definition_object("null").is_some());
    }

    #[test]
    fn test_domain_maps_get_status_coverage() {
        let mut domains = DomainMaps::default();
        domains
            .hash_algorithms
            .insert("sha256".to_string(), RequirementLevel::Mandatory);
        domains
            .ecc_curves
            .insert("nist_p256".to_string(), RequirementLevel::Recommended);
        domains
            .rsa_key_sizes
            .insert(2048, RequirementLevel::Mandatory);
        domains
            .asymmetric_schemes
            .insert("rsassa".to_string(), RequirementLevel::Optional);
        domains
            .symmetric_ciphers
            .insert("aes128_cfb".to_string(), RequirementLevel::Deprecated);
        domains
            .commands
            .insert("TPM2_CC_STARTUP".to_string(), RequirementLevel::Mandatory);

        assert_eq!(
            domains.get_status("sha256"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            domains.get_status("nist_p256"),
            Some(RequirementLevel::Recommended)
        );
        assert_eq!(
            domains.get_status("2048"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            domains.get_status("rsa2048"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            domains.get_status("rsassa"),
            Some(RequirementLevel::Optional)
        );
        assert_eq!(
            domains.get_status("aes128_cfb"),
            Some(RequirementLevel::Deprecated)
        );
        assert_eq!(
            domains.get_status("TPM2_CC_Startup"),
            Some(RequirementLevel::Mandatory)
        );
        assert_eq!(
            domains.get_status("startup"),
            Some(RequirementLevel::Mandatory)
        );
    }

    #[test]
    fn test_is_unsupported_algorithm_error() {
        use std::convert::TryFrom;
        use tss_esapi::constants::response_code::Tss2ResponseCode;

        let make_tss_err = |code: u32| -> anyhow::Error {
            let rc = Tss2ResponseCode::try_from(code).unwrap();
            anyhow::Error::new(TssError::Tss2Error(rc)).context("TPM operation failed")
        };

        // Format-1 unsupported algorithm codes (parameter 2: 0x2c0 + error_number)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c1))); // TPM_RC_ASYMMETRIC (1)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c2))); // TPM_RC_ATTRIBUTES (2)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c3))); // TPM_RC_HASH (3)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c4))); // TPM_RC_VALUE (4)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c7))); // TPM_RC_KEY_SIZE (7)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c8))); // TPM_RC_MGF (8)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2c9))); // TPM_RC_MODE (9)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2ca))); // TPM_RC_TYPE (10)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2cc))); // TPM_RC_KDF (12)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2d2))); // TPM_RC_SCHEME (0x12 = 18)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2d6))); // TPM_RC_SYMMETRIC (0x16 = 22)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x2e6))); // TPM_RC_CURVE (0x26 = 38)

        // Format-1 unsupported algorithm codes on a different parameter (e.g. parameter 1: 0x1d6)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x1d6))); // TPM_RC_SYMMETRIC + TPM_RC_P + TPM_RC_1

        // Format-0 unsupported command code (0x143 = TPM_RC_COMMAND_CODE)
        assert!(is_unsupported_algorithm_error(&make_tss_err(0x143)));

        // Non-algorithm TPM errors (0x2cb = TPM_RC_HANDLE, 0x101 = TPM_RC_FAILURE)
        assert!(!is_unsupported_algorithm_error(&make_tss_err(0x2cb)));
        assert!(!is_unsupported_algorithm_error(&make_tss_err(0x101)));

        // Non-TSS anyhow error
        assert!(!is_unsupported_algorithm_error(&anyhow::anyhow!(
            "connection refused"
        )));
    }
}
