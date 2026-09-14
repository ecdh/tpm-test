use enumflags2::{bitflags, BitFlags};

/// Test classification bitflags used by `TestCaseMetadata` and runtime filters (`TPM_TEST_CATEGORY` / `TPM_TEST_EXCLUDE_CATEGORY`).
///
/// Variants are ordered in three logical tiers (`Scope` -> `TPM Functional Domain` -> `Execution Trait`)
/// so that `BitFlags<TestCategory>` formats in a consistent `[Compliance, <Domain>, Smoke/Slow]` order.
#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TestCategory {
    // 1. Test Scope
    Compliance = 1 << 0, // Baseline TCG specification compliance
    Extended = 1 << 1,   // Extended / supplementary tests (go-tpm, tpm2-tss parity)

    // 2. TPM Functional Domain
    Pcr = 1 << 2,     // PCR banks, allocation, extend, reset
    Nv = 1 << 3,      // NV index define, read/write, locks, policies
    Asym = 1 << 4,    // RSA / ECC key generation, signing, ECDAA, KEM
    Sym = 1 << 5,     // Symmetric encryption, parameter decryption, CFB/CBC
    Hash = 1 << 6,    // Hash sequences, event sequences
    Attest = 1 << 7,  // Quotes, certification, audit logs
    Policy = 1 << 8,  // Authorization policies (PolicyOR, PolicySecret, PolicyPCR)
    Session = 1 << 9, // Sessions, audit, encryption, DA lockout

    // 3. Execution / Presubmit Trait
    Slow = 1 << 10,  // Long-running prime tests, exhaustive key sweeps
    Smoke = 1 << 11, // Fast pre-submit sanity checks
}

impl TestCategory {
    /// Default test categories (`Compliance | Smoke`) applied when none are specified.
    pub fn default_categories() -> BitFlags<Self> {
        Self::Compliance | Self::Smoke
    }
}

pub fn parse_category(s: &str) -> Option<TestCategory> {
    match s.trim().to_lowercase().as_str() {
        "compliance" => Some(TestCategory::Compliance),
        "extended" => Some(TestCategory::Extended),
        "pcr" => Some(TestCategory::Pcr),
        "nv" => Some(TestCategory::Nv),
        "asym" | "asymmetric" => Some(TestCategory::Asym),
        "sym" | "symmetric" => Some(TestCategory::Sym),
        "hash" => Some(TestCategory::Hash),
        "attest" | "attestation" => Some(TestCategory::Attest),
        "policy" => Some(TestCategory::Policy),
        "session" => Some(TestCategory::Session),
        "slow" => Some(TestCategory::Slow),
        "smoke" => Some(TestCategory::Smoke),
        _ => None,
    }
}

/// TCG Hierarchy and Permanent Authorization Domains required by a test.
#[bitflags]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TestHierarchy {
    Null = 1 << 0,        // TPM_RH_NULL (Standard unprivileged user / object auth)
    Owner = 1 << 1,       // TPM_RH_OWNER (Storage / OS admin hierarchy)
    Platform = 1 << 2,    // TPM_RH_PLATFORM (Firmware / pre-boot platform hierarchy)
    Endorsement = 1 << 3, // TPM_RH_ENDORSEMENT (Privacy / EK hierarchy)
    Lockout = 1 << 4,     // TPM_RH_LOCKOUT (Dictionary attack lockout authority)
}

impl TestHierarchy {
    /// Default TPM hierarchy (`Null`) applied when none are specified.
    pub fn default_hierarchies() -> BitFlags<Self> {
        BitFlags::from_flag(Self::Null)
    }
}

pub fn parse_hierarchy(s: &str) -> Option<TestHierarchy> {
    match s.trim().to_lowercase().as_str() {
        "null" | "standard" | "user" => Some(TestHierarchy::Null),
        "owner" | "admin" | "storage" => Some(TestHierarchy::Owner),
        "platform" | "firmware" => Some(TestHierarchy::Platform),
        "endorsement" | "ek" => Some(TestHierarchy::Endorsement),
        "lockout" | "da" => Some(TestHierarchy::Lockout),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct TestCaseMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub categories: BitFlags<TestCategory>,
    pub hierarchies: BitFlags<TestHierarchy>,
    pub sim_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FilterArgs {
    /// Include only tests matching specified categories (comma-separated, e.g. "compliance,pcr").
    pub category: Vec<String>,

    /// Exclude tests matching specified categories (comma-separated, e.g. "slow").
    pub exclude_category: Vec<String>,

    /// Allowed TPM hierarchies (comma-separated, e.g. "null,owner,platform").
    /// Defaults to all hierarchies enabled if empty.
    pub hierarchies: Vec<String>,

    /// Whether the test environment targets a physical hardware TPM (`TPM_IS_HARDWARE`).
    pub is_hardware: bool,

    /// Whether the test environment is running in dry-run mode (`DRY_RUN`).
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterDecision {
    Run,
    Excluded(String),
}

fn parse_csv_env(var: &str) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

impl FilterArgs {
    /// Constructs FilterArgs from standard environment variables:
    /// - `TPM_TEST_CATEGORY`
    /// - `TPM_TEST_EXCLUDE_CATEGORY`
    /// - `TPM_TEST_HIERARCHIES`
    /// - `TPM_IS_HARDWARE`
    /// - `DRY_RUN`
    pub fn from_env() -> Self {
        Self {
            category: parse_csv_env("TPM_TEST_CATEGORY"),
            exclude_category: parse_csv_env("TPM_TEST_EXCLUDE_CATEGORY"),
            hierarchies: parse_csv_env("TPM_TEST_HIERARCHIES"),
            is_hardware: crate::is_hardware_env(),
            dry_run: crate::is_dry_run_env(),
        }
    }
}

impl TestCaseMetadata {
    pub const fn new(
        name: &'static str,
        description: &'static str,
        categories: BitFlags<TestCategory>,
        hierarchies: BitFlags<TestHierarchy>,
        sim_only: bool,
    ) -> Self {
        Self {
            name,
            description,
            categories,
            hierarchies,
            sim_only,
        }
    }

    pub fn matches_filter(&self, filter: &FilterArgs) -> bool {
        matches!(self.evaluate(filter), FilterDecision::Run)
    }

    /// Evaluates if the test should run based on the current environment configuration.
    /// Logs a debug message if excluded and returns `true` (run) or `false` (skip).
    pub fn should_run(&self) -> bool {
        let filter = FilterArgs::from_env();
        match self.evaluate(&filter) {
            FilterDecision::Run => {
                if filter.dry_run {
                    log::info!(
                        "[DRY RUN] Would execute {}: {} (categories: {:?}, hierarchies: {:?}, sim_only: {})",
                        self.name,
                        self.description,
                        self.categories,
                        self.hierarchies,
                        self.sim_only
                    );
                    false
                } else {
                    true
                }
            }
            FilterDecision::Excluded(reason) => {
                log::info!("[FILTER EXCLUDED] {}: {}", self.name, reason);
                false
            }
        }
    }

    pub fn evaluate(&self, filter: &FilterArgs) -> FilterDecision {
        // 0. Check simulator-only restriction on hardware targets
        if self.sim_only && filter.is_hardware {
            return FilterDecision::Excluded(
                "Test is marked sim_only and hardware target is active (TPM_IS_HARDWARE=true)"
                    .to_string(),
            );
        }

        // 1. Check hierarchies (ensure all hierarchies required by the test are allowed in the environment)
        if !filter.hierarchies.is_empty() {
            let mut allowed_flags = BitFlags::<TestHierarchy>::empty();
            for h in &filter.hierarchies {
                if let Some(parsed) = parse_hierarchy(h) {
                    allowed_flags |= parsed;
                }
            }

            if !allowed_flags.contains(self.hierarchies) {
                return FilterDecision::Excluded(format!(
                    "Test required hierarchies ({:?}) not fully satisfied by allowed hierarchies ({:?})",
                    self.hierarchies, allowed_flags
                ));
            }
        }

        // 2. Check category exclusion
        for excl in &filter.exclude_category {
            if let Some(cat) = parse_category(excl) {
                if self.categories.contains(cat) {
                    return FilterDecision::Excluded(format!("Excluded by category: {}", excl));
                }
            }
        }

        // 3. Check category inclusion (if any specified)
        if !filter.category.is_empty() {
            let mut matched = false;
            for incl in &filter.category {
                if let Some(cat) = parse_category(incl) {
                    if self.categories.contains(cat) {
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return FilterDecision::Excluded(
                    "Does not match specified inclusion categories".to_string(),
                );
            }
        }

        FilterDecision::Run
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_and_hierarchies_metadata_evaluation() {
        let pcr_meta = TestCaseMetadata {
            name: "test_pcr_extend",
            description: "Test PCR extend and read",
            categories: TestCategory::Compliance | TestCategory::Pcr | TestCategory::Smoke,
            hierarchies: TestHierarchy::Null.into(),
            sim_only: false,
        };

        let ak_meta = TestCaseMetadata {
            name: "test_ak_activation",
            description: "Attestation key creation and activation under EK and SRK",
            categories: TestCategory::Compliance | TestCategory::Attest,
            hierarchies: TestHierarchy::Owner | TestHierarchy::Endorsement,
            sim_only: false,
        };

        let platform_meta = TestCaseMetadata {
            name: "test_platform_nv_define",
            description: "Platform hierarchy NV space test",
            categories: TestCategory::Compliance | TestCategory::Nv,
            hierarchies: TestHierarchy::Platform.into(),
            sim_only: true,
        };

        // 1. Matches category inclusion
        let filter_pcr = FilterArgs {
            category: vec!["pcr".to_string()],
            ..Default::default()
        };
        assert_eq!(pcr_meta.evaluate(&filter_pcr), FilterDecision::Run);
        assert!(pcr_meta.matches_filter(&filter_pcr));

        // 2. Excluded by category
        let filter_no_smoke = FilterArgs {
            exclude_category: vec!["smoke".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            pcr_meta.evaluate(&filter_no_smoke),
            FilterDecision::Excluded(_)
        ));
        assert!(!pcr_meta.matches_filter(&filter_no_smoke));

        // 3. Hierarchies filter: OS user runtime with only Null and Owner
        let filter_os_runtime = FilterArgs {
            hierarchies: vec!["null".to_string(), "owner".to_string()],
            ..Default::default()
        };
        assert!(pcr_meta.matches_filter(&filter_os_runtime));
        assert!(!platform_meta.matches_filter(&filter_os_runtime)); // Platform missing
        assert!(!ak_meta.matches_filter(&filter_os_runtime)); // Endorsement missing

        // 4. Hierarchies filter: Full admin environment with Null, Owner, Endorsement
        let filter_full_admin = FilterArgs {
            hierarchies: vec![
                "null".to_string(),
                "owner".to_string(),
                "endorsement".to_string(),
            ],
            ..Default::default()
        };
        assert!(pcr_meta.matches_filter(&filter_full_admin));
        assert!(ak_meta.matches_filter(&filter_full_admin)); // Owner + Endorsement satisfied!
        assert!(!platform_meta.matches_filter(&filter_full_admin)); // Platform missing

        // 5. sim_only filter: runs when is_hardware is false, skipped when is_hardware is true
        let filter_sim = FilterArgs {
            is_hardware: false,
            ..Default::default()
        };
        assert!(platform_meta.matches_filter(&filter_sim));

        let filter_hw = FilterArgs {
            is_hardware: true,
            ..Default::default()
        };
        assert!(pcr_meta.matches_filter(&filter_hw));
        assert!(!platform_meta.matches_filter(&filter_hw));
    }

    #[test]
    fn test_defaults() {
        assert_eq!(
            TestCategory::default_categories(),
            TestCategory::Compliance | TestCategory::Smoke
        );
        assert_eq!(
            TestHierarchy::default_hierarchies(),
            BitFlags::from_flag(TestHierarchy::Null)
        );
    }
}
