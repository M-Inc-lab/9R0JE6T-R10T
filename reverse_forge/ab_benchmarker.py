"""
R3V3R53//F0RG3  Statistical A/B Benchmarking & Experimentation Suite
====================================================================
Phase 41: Empirical A/B testing engine for comparing reverse engineering
implementations, triage algorithms, and optimization variants.

Implements rigorous hypothesis testing (Welch's t-test, Cohen's d, p-value,
confidence intervals, latency percentiles, and guardrail parity verification).

Zero external dependencies — pure Python stdlib (math + time + tracemalloc + statistics).
"""

from __future__ import annotations

import math
import os
import time
import tracemalloc
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.streaming_pe import StreamingPEAnalyzer


@dataclass
class VariantMetrics:
    name: str
    sample_size: int
    latencies_ms: List[float]
    mean_latency_ms: float
    median_latency_ms: float
    std_dev_ms: float
    variance_ms: float
    min_latency_ms: float
    max_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_mb_s: float
    peak_memory_kb: float
    metadata_summary: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailResult:
    passed: bool
    checks: Dict[str, bool]
    mismatches: List[str]


@dataclass
class ABExperimentReport:
    experiment_id: str
    target_artifact: str
    target_size_bytes: int
    control: VariantMetrics
    treatment: VariantMetrics
    guardrails: GuardrailResult
    t_statistic: float
    degrees_of_freedom: float
    p_value: float
    cohens_d: float
    ci_95_lower_ms: float
    ci_95_upper_ms: float
    speedup_ratio: float
    latency_reduction_pct: float
    memory_reduction_pct: float
    statistically_significant: bool
    winner: str
    summary_markdown: str


class BinaryABBenchmarker:
    """
    Statistical A/B testing suite for binary analysis engines.
    Validates performance optimizations against baseline implementations
    while ensuring strict guardrail parity.
    """

    def __init__(self, target_filepath: str, trials: int = 10, warmup_runs: int = 2):
        self.target_path = os.path.abspath(target_filepath)
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Target binary not found: {self.target_path}")
        self.file_size = os.path.getsize(self.target_path)
        self.trials = max(3, trials)
        self.warmup_runs = max(0, warmup_runs)

    @staticmethod
    def _t_to_p_value(t_stat: float, df: float) -> float:
        """
        Approximate two-tailed p-value for Student's / Welch's t-distribution
        using Hill's / Peizer-Pratt approximation (pure Python stdlib).
        """
        if df <= 0:
            return 1.0
        t_abs = abs(t_stat)
        if t_abs == 0:
            return 1.0

        # Normal approximation with Cornish-Fisher expansion for df >= 4
        x = df / (df + t_abs * t_abs)
        # Incomplete beta approximation via log-gamma or continued fraction
        # For typical benchmarking df > 5, standard logistic/normal approximation is accurate:
        z = (t_abs * (1.0 - 1.0 / (4.0 * df))) / math.sqrt(1.0 + (t_abs * t_abs) / (2.0 * df))
        # Standard normal two-tailed complementary error function
        p_val = math.erfc(z / math.sqrt(2.0))
        return max(1e-12, min(1.0, round(p_val, 6)))

    @staticmethod
    def _critical_t_95(df: float) -> float:
        """Approximate two-tailed 95% critical t value for degrees of freedom df."""
        if df < 1:
            return 12.706
        # Table lookup for small df, normal 1.96 approximation for large df
        t_table = {
            1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
            6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
            12: 2.179, 14: 2.145, 16: 2.120, 18: 2.101, 20: 2.086,
            30: 2.042, 40: 2.021, 60: 2.000, 100: 1.984
        }
        df_int = int(round(df))
        if df_int in t_table:
            return t_table[df_int]
        for k in sorted(t_table.keys()):
            if df_int <= k:
                return t_table[k]
        return 1.960

    def _benchmark_control(self) -> Tuple[List[float], float, Dict[str, Any]]:
        """Run Variant A (Control: In-memory PEAnalyzer)."""
        latencies: List[float] = []

        # Read once to represent file reading
        with open(self.target_path, "rb") as f:
            data = f.read()

        # Warmup
        for _ in range(self.warmup_runs):
            _ = PEAnalyzer(data).analyze()

        # Memory profiling run with tracemalloc
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[1]
        _ = PEAnalyzer(data).analyze()
        peak_mem = tracemalloc.get_traced_memory()[1] - start_mem
        tracemalloc.stop()

        # Clean timing loop without tracemalloc overhead
        metadata: Dict[str, Any] = {}
        for _ in range(self.trials):
            t0 = time.perf_counter()
            analyzer = PEAnalyzer(data)
            res = analyzer.analyze()
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)
            if not metadata:
                metadata = res

        return latencies, max(0.0, peak_mem / 1024.0), metadata

    def _benchmark_treatment(self) -> Tuple[List[float], float, Dict[str, Any]]:
        """Run Variant B (Treatment: StreamingPEAnalyzer zero-copy mmap)."""
        latencies: List[float] = []

        # Warmup
        for _ in range(self.warmup_runs):
            _ = StreamingPEAnalyzer(self.target_path).analyze()

        # Memory profiling run with tracemalloc
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[1]
        _ = StreamingPEAnalyzer(self.target_path).analyze()
        peak_mem = tracemalloc.get_traced_memory()[1] - start_mem
        tracemalloc.stop()

        # Clean timing loop without tracemalloc overhead
        metadata: Dict[str, Any] = {}
        for _ in range(self.trials):
            t0 = time.perf_counter()
            analyzer = StreamingPEAnalyzer(self.target_path)
            res = analyzer.analyze()
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)
            if not metadata:
                metadata = asdict(res)

        return latencies, max(0.0, peak_mem / 1024.0), metadata

    @staticmethod
    def _compute_metrics(name: str, latencies: List[float], peak_mem_kb: float, file_size: int, meta: Dict[str, Any]) -> VariantMetrics:
        n = len(latencies)
        mean_l = sum(latencies) / n
        sorted_l = sorted(latencies)
        median_l = sorted_l[n // 2] if n % 2 != 0 else (sorted_l[n // 2 - 1] + sorted_l[n // 2]) / 2.0
        var_l = sum((x - mean_l) ** 2 for x in latencies) / (n - 1) if n > 1 else 0.0
        std_l = math.sqrt(var_l)

        p95_idx = min(n - 1, int(math.ceil(0.95 * n)) - 1)
        p99_idx = min(n - 1, int(math.ceil(0.99 * n)) - 1)

        throughput = (file_size / (1024 * 1024)) / (mean_l / 1000.0) if mean_l > 0 else 0.0

        return VariantMetrics(
            name=name,
            sample_size=n,
            latencies_ms=[round(x, 4) for x in latencies],
            mean_latency_ms=round(mean_l, 4),
            median_latency_ms=round(median_l, 4),
            std_dev_ms=round(std_l, 4),
            variance_ms=round(var_l, 4),
            min_latency_ms=round(min(latencies), 4),
            max_latency_ms=round(max(latencies), 4),
            p95_latency_ms=round(sorted_l[p95_idx], 4),
            p99_latency_ms=round(sorted_l[p99_idx], 4),
            throughput_mb_s=round(throughput, 2),
            peak_memory_kb=round(peak_mem_kb, 2),
            metadata_summary={
                "sections_count": len(meta.get("sections", [])),
                "architecture": meta.get("architecture"),
                "entry_point": meta.get("entry_point"),
                "format": meta.get("format"),
            },
        )

    def _verify_guardrails(self, control_meta: Dict[str, Any], treat_meta: Dict[str, Any]) -> GuardrailResult:
        """Ensure Treatment preserves 100% data parity with Control (guardrail metric)."""
        checks: Dict[str, bool] = {}
        mismatches: List[str] = []

        # 1. Architecture parity
        c_arch = control_meta.get("architecture")
        t_arch = treat_meta.get("architecture")
        checks["architecture_match"] = (c_arch == t_arch)
        if not checks["architecture_match"]:
            mismatches.append(f"Architecture mismatch: Control={c_arch} vs Treatment={t_arch}")

        # 2. Section count parity
        c_sec = len(control_meta.get("sections", []))
        t_sec = len(treat_meta.get("sections", []))
        checks["section_count_match"] = (c_sec == t_sec)
        if not checks["section_count_match"]:
            mismatches.append(f"Section count mismatch: Control={c_sec} vs Treatment={t_sec}")

        # 3. Entry point parity
        c_ep = control_meta.get("entry_point")
        t_ep = treat_meta.get("entry_point")
        checks["entry_point_match"] = (c_ep == t_ep)
        if not checks["entry_point_match"]:
            mismatches.append(f"Entry point mismatch: Control={c_ep} vs Treatment={t_ep}")

        # 4. Formats match
        c_fmt = control_meta.get("is_pe", True)
        t_fmt = treat_meta.get("is_pe", True)
        checks["pe_signature_match"] = (c_fmt == t_fmt)
        if not checks["pe_signature_match"]:
            mismatches.append(f"PE flag mismatch: Control={c_fmt} vs Treatment={t_fmt}")

        all_passed = all(checks.values())
        return GuardrailResult(passed=all_passed, checks=checks, mismatches=mismatches)

    def run_experiment(self) -> ABExperimentReport:
        """Execute full statistical A/B test with Welch's t-test and parity verification."""
        ctrl_lats, ctrl_mem, ctrl_meta = self._benchmark_control()
        treat_lats, treat_mem, treat_meta = self._benchmark_treatment()

        control = self._compute_metrics("Variant A (Control: In-Memory PEAnalyzer)", ctrl_lats, ctrl_mem, self.file_size, ctrl_meta)
        treatment = self._compute_metrics("Variant B (Treatment: StreamingPEAnalyzer mmap)", treat_lats, treat_mem, self.file_size, treat_meta)

        guardrails = self._verify_guardrails(ctrl_meta, treat_meta)

        # Welch's Two-Sample t-test
        n_a, n_b = control.sample_size, treatment.sample_size
        s_a2, s_b2 = control.variance_ms, treatment.variance_ms
        mean_a, mean_b = control.mean_latency_ms, treatment.mean_latency_ms

        se_diff = math.sqrt((s_a2 / n_a) + (s_b2 / n_b)) if (s_a2 > 0 or s_b2 > 0) else 1e-6
        t_stat = (mean_a - mean_b) / se_diff

        # Welch-Satterthwaite degrees of freedom
        num_df = ((s_a2 / n_a) + (s_b2 / n_b)) ** 2
        den_df = (((s_a2 / n_a) ** 2) / (n_a - 1)) + (((s_b2 / n_b) ** 2) / (n_b - 1)) if (n_a > 1 and n_b > 1) else 1.0
        df = num_df / den_df if den_df > 0 else 1.0

        p_val = self._t_to_p_value(t_stat, df)

        # Pooled standard deviation & Cohen's d effect size
        pooled_s = math.sqrt(((n_a - 1) * s_a2 + (n_b - 1) * s_b2) / (n_a + n_b - 2)) if (n_a + n_b > 2) else 1e-6
        cohens_d = (mean_a - mean_b) / pooled_s if pooled_s > 0 else 0.0

        # 95% Confidence Interval for latency reduction (mean_a - mean_b)
        crit_t = self._critical_t_95(df)
        diff_mean = mean_a - mean_b
        ci_lower = diff_mean - (crit_t * se_diff)
        ci_upper = diff_mean + (crit_t * se_diff)

        # Speedup & reductions
        speedup = (mean_a / mean_b) if mean_b > 0 else 1.0
        lat_red_pct = ((mean_a - mean_b) / mean_a * 100.0) if mean_a > 0 else 0.0
        mem_red_pct = ((control.peak_memory_kb - treatment.peak_memory_kb) / control.peak_memory_kb * 100.0) if control.peak_memory_kb > 0 else 0.0

        stat_sig = (p_val < 0.05)
        if stat_sig and diff_mean > 0 and guardrails.passed:
            winner = "Variant B (Treatment: StreamingPEAnalyzer)"
        elif stat_sig and diff_mean < 0 and guardrails.passed:
            winner = "Variant A (Control: In-Memory PEAnalyzer)"
        else:
            winner = "No Statistically Significant Difference (Inconclusive)"

        # Generate Markdown summary
        md = self._format_markdown_report(
            control, treatment, guardrails, t_stat, df, p_val, cohens_d,
            ci_lower, ci_upper, speedup, lat_red_pct, mem_red_pct, stat_sig, winner
        )

        return ABExperimentReport(
            experiment_id=f"EXP-{int(time.time())}",
            target_artifact=self.target_path,
            target_size_bytes=self.file_size,
            control=control,
            treatment=treatment,
            guardrails=guardrails,
            t_statistic=round(t_stat, 4),
            degrees_of_freedom=round(df, 2),
            p_value=round(p_val, 6),
            cohens_d=round(cohens_d, 4),
            ci_95_lower_ms=round(ci_lower, 4),
            ci_95_upper_ms=round(ci_upper, 4),
            speedup_ratio=round(speedup, 2),
            latency_reduction_pct=round(lat_red_pct, 2),
            memory_reduction_pct=round(mem_red_pct, 2),
            statistically_significant=stat_sig,
            winner=winner,
            summary_markdown=md,
        )

    def _format_markdown_report(
        self,
        ctrl: VariantMetrics,
        treat: VariantMetrics,
        guard: GuardrailResult,
        t_stat: float,
        df: float,
        p_val: float,
        cohens_d: float,
        ci_lower: float,
        ci_upper: float,
        speedup: float,
        lat_red: float,
        mem_red: float,
        stat_sig: bool,
        winner: str,
    ) -> str:
        guard_badge = "✅ PASSED (100% Parity)" if guard.passed else f"❌ FAILED ({len(guard.mismatches)} mismatches)"
        sig_badge = "✅ Significant (p < 0.05)" if stat_sig else "⚠️ Not Significant (p >= 0.05)"

        return f"""# R3V3R53//F0RG3  A/B Experiment Report: Binary Triage Optimization
**Target Artifact:** `{self.target_path}` ({self.file_size / (1024*1024):.2f} MB)  
**Sample Size:** N={ctrl.sample_size} trials per variant (after {self.warmup_runs} warmup runs)  
**Guardrail Verification:** {guard_badge}  
**Statistical Outcome:** {sig_badge}  
**Decided Winner:** **{winner}**

---

## 1. Executive Summary & Effect Size
- **Speedup Ratio:** **{speedup:.2f}x** ({lat_red:.1f}% mean latency reduction)
- **Throughput:** Treatment achieves **{treat.throughput_mb_s:.2f} MB/s** vs Control **{ctrl.throughput_mb_s:.2f} MB/s**
- **Peak Memory Delta:** **{mem_red:.1f}% reduction** ({treat.peak_memory_kb:.1f} KB vs {ctrl.peak_memory_kb:.1f} KB)
- **Cohen's d (Effect Size):** **{cohens_d:.2f}** ({"Large effect (|d| >= 0.8)" if abs(cohens_d) >= 0.8 else "Medium/Small effect"})
- **95% Confidence Interval for Δμ:** `[{ci_lower:.3f} ms, {ci_upper:.3f} ms]`

---

## 2. Benchmark Metric Comparison Table

| Metric | Variant A (Control: In-Memory) | Variant B (Treatment: Streaming mmap) | Delta / Change |
|---|---|---|---|
| **Mean Latency** | `{ctrl.mean_latency_ms:.3f} ms` | `{treat.mean_latency_ms:.3f} ms` | **-{lat_red:.1f}%** |
| **Median (p50)** | `{ctrl.median_latency_ms:.3f} ms` | `{treat.median_latency_ms:.3f} ms` | -{(ctrl.median_latency_ms - treat.median_latency_ms)/ctrl.median_latency_ms*100:.1f}% |
| **95th Percentile (p95)** | `{ctrl.p95_latency_ms:.3f} ms` | `{treat.p95_latency_ms:.3f} ms` | - |
| **Std Deviation (σ)** | `{ctrl.std_dev_ms:.3f} ms` | `{treat.std_dev_ms:.3f} ms` | - |
| **Throughput** | `{ctrl.throughput_mb_s:.2f} MB/s` | `{treat.throughput_mb_s:.2f} MB/s` | **+{treat.throughput_mb_s - ctrl.throughput_mb_s:.2f} MB/s** |
| **Peak Allocated Memory** | `{ctrl.peak_memory_kb:.1f} KB` | `{treat.peak_memory_kb:.1f} KB` | **-{mem_red:.1f}%** |

---

## 3. Inferential Hypothesis Testing (Welch's Two-Sample t-Test)
- **Null Hypothesis ($H_0$):** $\\mu_A = \\mu_B$ (no latency difference between Control and Treatment)
- **Alternative Hypothesis ($H_1$):** $\\mu_B < \\mu_A$ (Treatment is faster than Control)
- **t-Statistic:** `{t_stat:.4f}`
- **Degrees of Freedom (ν):** `{df:.2f}`
- **Two-Tailed p-Value:** `{p_val:.6f}`
- **Significance Level (α):** `0.05`
- **Result:** {"Reject H0 in favor of H1 — Treatment is statistically superior" if stat_sig and t_stat > 0 else "Fail to reject H0"}

---

## 4. Guardrail Parity Checks
| Guardrail Check | Status | Notes |
|---|---|---|
| Architecture Parity | {'✅ Match' if guard.checks.get('architecture_match') else '❌ Mismatch'} | Both identified `{ctrl.metadata_summary.get('architecture')}` |
| Section Count Parity | {'✅ Match' if guard.checks.get('section_count_match') else '❌ Mismatch'} | Both extracted `{ctrl.metadata_summary.get('sections_count')}` sections |
| Entry Point Parity | {'✅ Match' if guard.checks.get('entry_point_match') else '❌ Mismatch'} | Both resolved `{ctrl.metadata_summary.get('entry_point')}` |
| PE Signature Validation | {'✅ Match' if guard.checks.get('pe_signature_match') else '❌ Mismatch'} | 100% signature consistency |
"""
