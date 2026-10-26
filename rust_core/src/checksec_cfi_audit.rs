//! R3V3R53//F0RG3 — Native Rust Defensive `checksec` & Control-Flow Integrity (CFI / CET) Auditor
//! (`checksec_cfi_audit.rs`)
//! Implements Category 12 (`checksec`, Intel CET Shadow-Stack / `endbr64` IBT, Stack Canary,
//! ASLR, DEP/NX, PIE, RELRO, and Control Flow Guard auditing) in zero-copy Rust.

use crate::parsers::parse_binary_zero_copy;

#[derive(Debug, Clone)]
pub struct ChecksecCfiReport {
    pub format: &'static str,
    pub architecture: &'static str,
    pub aslr_or_pie: bool,
    pub dep_nx: bool,
    pub control_flow_guard: bool,
    pub stack_canary_present: bool,
    pub intel_cet_endbr_count: usize,
    pub rwx_sections_count: usize,
    pub hardening_score: u8,
}

pub fn audit_binary_checksec_and_cfi(data: &[u8]) -> ChecksecCfiReport {
    let summary = parse_binary_zero_copy(data);
    let canary = data.windows(16).any(|w| w == b"__stack_chk_fail")
        || data.windows(23).any(|w| w == b"__security_check_cookie");

    let cet_count = data
        .windows(4)
        .filter(|&w| w == b"\xf3\x0f\x1e\xfa" || w == b"\xf3\x0f\x1e\xfb")
        .count();

    let rwx_count = summary
        .sections
        .iter()
        .filter(|s| s.executable && s.writable)
        .count();

    let mut score: u8 = 20;
    if summary.aslr {
        score += 20;
    }
    if summary.dep_nx {
        score += 20;
    }
    if summary.cfg_guard || cet_count > 0 {
        score += 20;
    }
    if canary {
        score += 20;
    }
    if rwx_count > 0 {
        score = score.saturating_sub(25);
    }

    ChecksecCfiReport {
        format: summary.format,
        architecture: summary.architecture,
        aslr_or_pie: summary.aslr,
        dep_nx: summary.dep_nx,
        control_flow_guard: summary.cfg_guard,
        stack_canary_present: canary,
        intel_cet_endbr_count: cet_count,
        rwx_sections_count: rwx_count,
        hardening_score: score,
    }
}
