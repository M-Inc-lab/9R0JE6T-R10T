//! R3V3R53//F0RG3 — Full-Fledged Standalone 16-Category Native Rust CLI (`main.rs`)
//! Subcommands:
//!   reverse-forge-rs all <binary_path>
//!   reverse-forge-rs triage <binary_path>
//!   reverse-forge-rs decompile <binary_path>
//!   reverse-forge-rs visor <binary_path>
//!   reverse-forge-rs bytecode <binary_path>
//!   reverse-forge-rs firmware <binary_path>
//!   reverse-forge-rs pcap <pcap_path>
//!   reverse-forge-rs checksec <binary_path>
//!   reverse-forge-rs memory <dump_or_pe_path>
//!   reverse-forge-rs imhex <binary_path> [pattern]
//!   reverse-forge-rs diff <primary_path> <secondary_path>

#![allow(warnings)]
#![allow(clippy::all)]

use std::env;
use std::fs;
use std::process;
use std::time::Instant;

use reverse_forge_core::bytecode_jvm_dex_clr_wasm::analyze_managed_bytecode;
use reverse_forge_core::checksec_cfi_audit::audit_binary_checksec_and_cfi;
use reverse_forge_core::diff_diaphora::diff_binaries_diaphora;
use reverse_forge_core::disasm::lift_bytes_to_pcode_blocks;
use reverse_forge_core::firmware_binwalk::scan_firmware_image;
use reverse_forge_core::imhex_patcher::evaluate_imhex_pattern;
use reverse_forge_core::memory_volatility_pesieve::analyze_memory_and_unmap_pe;
use reverse_forge_core::network_pcap_netzob::dissect_pcap_and_infer_protocol;
use reverse_forge_core::parsers::parse_binary_zero_copy;
use reverse_forge_core::pcode_ssa::GhidraPcodeDecompiler;
use reverse_forge_core::scanner::{compute_flirt_crc16, fnv1a_64, scan_builtin_signatures};
use reverse_forge_core::visor::RustMicroVisor;
use reverse_forge_core::deobfuscation_floss_mba::deobfuscate_strings_and_crypto;
use reverse_forge_core::symbols_rtti_golang_rust_pdb::analyze_symbols_rtti_pdb_syscalls;
use reverse_forge_core::taint_vsa_vuln_scanner::RustTaintVsaVulnEngine;
use reverse_forge_core::yara_sigma_bridge_containers::synthesize_yara_sigma_and_layer2_bridge;
use reverse_forge_core::elf_macho_deep::{audit_elf_deep, audit_macho_deep};
use reverse_forge_core::pipeline_sarif_sbom_rfdb::run_12_stage_pipeline_rust;
use reverse_forge_core::deobfuscators_advanced_open_source::{inspect_and_locate_upx_oep, scan_function_boundaries_rizin};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("9R0JE6T-R10T // R3V3R53-F0RG3 Standalone 16-Category Native Rust Suite (v26.0.0-rust-bicentennial)");
        eprintln!("Usage: {} <all|triage|decompile|visor|bytecode|firmware|pcap|checksec|memory|imhex|diff> <target> [target2_or_pattern]", args[0]);
        process::exit(1);
    }

    let cmd = args[1].as_str();
    let path = &args[2];
    let t0 = Instant::now();

    let mut data = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Failed to read '{}': {}", path, e);
            process::exit(1);
        }
    };

    if cmd == "diff" {
        if args.len() < 4 {
            eprintln!("Usage: {} diff <primary_binary> <secondary_binary>", args[0]);
            process::exit(1);
        }
        let sec_data = fs::read(&args[3]).unwrap_or_default();
        let dres = diff_binaries_diaphora(&data, &sec_data, 0x401000);
        println!(
            "{{\"classification\": \"{}\", \"similarity\": {:.4}, \"spp_match\": {}, \"primary_fnv1a\": \"0x{:016x}\", \"secondary_fnv1a\": \"0x{:016x}\"}}",
            dres.classification, dres.overall_similarity_score, dres.spp_prime_product_match, dres.primary_fnv1a, dres.secondary_fnv1a
        );
        return;
    }

    let summary = parse_binary_zero_copy(&data);
    let hits = scan_builtin_signatures(&data);
    let crc16 = compute_flirt_crc16(&data[..data.len().min(64)]);
    let fnv = fnv1a_64(&data);
    let cfi = audit_binary_checksec_and_cfi(&data);
    let fw = scan_firmware_image(&data);
    let bc = analyze_managed_bytecode(&data);

    match cmd {
        "all" | "triage" => {
            let code_slice = &data[..data.len().min(512)];
            let blocks = lift_bytes_to_pcode_blocks(code_slice, summary.entry_point_va);
            let pcode_res = GhidraPcodeDecompiler::emit_structured_c(
                &blocks,
                "entry_main",
                summary.entry_point_va,
            );
            let mut visor = RustMicroVisor::new(summary.entry_point_va);
            let vres = visor.execute(summary.entry_point_va, code_slice, 128);
            let elapsed_us = t0.elapsed().as_micros();

            println!("{{");
            println!(
                "  \"engine\": \"reverse-forge-rs (16-Category Standalone Native Rust Suite)\","
            );
            println!("  \"version\": \"26.0.0-rust-bicentennial\",");
            println!("  \"elapsed_microseconds\": {},", elapsed_us);
            println!("  \"format\": \"{}\",", summary.format);
            println!("  \"architecture\": \"{}\",", summary.architecture);
            println!("  \"size_bytes\": {},", summary.size_bytes);
            println!("  \"entropy\": {:.4},", summary.entropy);
            println!("  \"entry_point_va\": \"0x{:x}\",", summary.entry_point_va);
            println!("  \"flirt_crc16_head\": \"0x{:04x}\",", crc16);
            println!("  \"fnv1a_64\": \"0x{:016x}\",", fnv);
            println!("  \"checksec_cfi\": {{ \"aslr\": {}, \"dep_nx\": {}, \"cfg\": {}, \"canary\": {}, \"cet_endbr_count\": {}, \"score\": {} }},",
                cfi.aslr_or_pie, cfi.dep_nx, cfi.control_flow_guard, cfi.stack_canary_present, cfi.intel_cet_endbr_count, cfi.hardening_score);
            println!("  \"bytecode_runtime\": \"{}\",", bc.runtime);
            println!(
                "  \"firmware_partitions_carved\": {},",
                fw.carved_partitions.len()
            );
            println!("  \"visor_execution\": {{ \"steps\": {}, \"auto_paged_faults\": {}, \"final_rax\": \"0x{:x}\" }},",
                vres.steps_executed, vres.auto_paged_faults, vres.final_rax);
            println!("  \"pcode_ops_lifted\": {},", pcode_res.total_pcode_ops);
            println!("  \"signature_hits_count\": {}", hits.len());
            println!("}}");
        }
        "decompile" => {
            let code_slice = &data[..data.len().min(512)];
            let blocks = lift_bytes_to_pcode_blocks(code_slice, summary.entry_point_va);
            let res = GhidraPcodeDecompiler::emit_structured_c(
                &blocks,
                "entry_main",
                summary.entry_point_va,
            );
            println!("{}", res.c_source);
        }
        "visor" => {
            let code_slice = &data[..data.len().min(512)];
            let mut visor = RustMicroVisor::new(summary.entry_point_va);
            let vres = visor.execute(summary.entry_point_va, code_slice, 128);
            println!(
                "{{\"steps\": {}, \"auto_paged_faults\": {}, \"final_rax\": \"0x{:x}\", \"halt_reason\": \"{}\"}}",
                vres.steps_executed, vres.auto_paged_faults, vres.final_rax, vres.halt_reason
            );
        }
        "bytecode" => {
            println!(
                "{{\"runtime\": \"{}\", \"version\": \"{}\", \"strings_count\": {}, \"tables_count\": {}}}",
                bc.runtime, bc.version_info, bc.constant_pool_or_strings.len(), bc.metadata_tables.len()
            );
            println!("{}", bc.decompiled_source);
        }
        "firmware" => {
            println!(
                "{{\"is_cortex_m\": {}, \"inferred_base\": \"0x{:x}\", \"partitions_count\": {}}}",
                fw.is_cortex_m_vector_table,
                fw.inferred_base_address,
                fw.carved_partitions.len()
            );
        }
        "pcap" => {
            let net = dissect_pcap_and_infer_protocol(&data);
            println!(
                "{{\"valid_pcap\": {}, \"packets\": {}, \"grammar\": {:?}}}",
                net.is_valid_pcap, net.total_packets, net.inferred_protocol_grammar
            );
        }
        "checksec" => {
            println!(
                "{{\"aslr\": {}, \"dep_nx\": {}, \"cfg\": {}, \"canary\": {}, \"cet_endbr\": {}, \"score\": {}}}",
                cfi.aslr_or_pie, cfi.dep_nx, cfi.control_flow_guard, cfi.stack_canary_present, cfi.intel_cet_endbr_count, cfi.hardening_score
            );
        }
        "memory" => {
            let mrep = analyze_memory_and_unmap_pe(&mut data);
            println!(
                "{{\"dump_type\": \"{}\", \"streams\": {}, \"hollowing_detected\": {}, \"repaired_sections\": {}}}",
                mrep.dump_type, mrep.streams_count, mrep.hollowing_or_tampering_detected, mrep.unmapped_sections_repaired
            );
        }
        "imhex" => {
            let pat = if args.len() >= 4 {
                args[3].as_str()
            } else {
                "struct Header { u16 magic; u16 cblp; u32 reserved; };"
            };
            let fields = evaluate_imhex_pattern(&data, 0, pat);
            for f in fields {
                println!(
                    "0x{:04x}: {} {} = {}",
                    f.offset, f.field_type, f.field_name, f.formatted_value
                );
            }
        }
        "deobfuscate" => {
            let deob = deobfuscate_strings_and_crypto(&data);
            println!(
                "{{\"stack_and_xor_strings\": {}, \"custom_b64_tables\": {}, \"rc4_ksa_hits\": {}}}",
                deob.stack_and_xor_strings.len(), deob.custom_base64_alphabets.len(), deob.rc4_ksa_offsets.len()
            );
        }
        "symbols" => {
            let syms = analyze_symbols_rtti_pdb_syscalls(&data, summary.image_base);
            println!(
                "{{\"cpp_rtti_classes\": {:?}, \"go_version\": {:?}, \"go_funcs\": {}, \"rust_symbols\": {:?}, \"syscalls\": {}}}",
                syms.cpp_rtti_classes, syms.go_version_family, syms.go_recovered_functions.len(), syms.demangled_rust_symbols, syms.direct_syscalls.len()
            );
        }
        "vuln-scan" => {
            let mut v_eng = RustTaintVsaVulnEngine::new();
            let v_rep = v_eng.audit_binary_and_insns(&data, &[], cfi.rwx_sections_count > 0);
            println!(
                "{{\"overall_risk\": \"{}\", \"critical\": {}, \"high\": {}, \"findings_count\": {}}}",
                v_rep.overall_risk, v_rep.critical_count, v_rep.high_count, v_rep.findings.len()
            );
        }
        "yara-bridge" => {
            let mut v_eng = RustTaintVsaVulnEngine::new();
            let v_rep = v_eng.audit_binary_and_insns(&data, &[], cfi.rwx_sections_count > 0);
            let bundle = synthesize_yara_sigma_and_layer2_bridge(
                &data,
                path,
                fnv,
                summary.entry_point_va,
                &v_rep.findings,
            );
            println!("{}", bundle.yara_rule);
        }
        "elf-deep" => {
            let erep = audit_elf_deep(&data);
            println!(
                "{{\"is_elf\": {}, \"type\": \"{}\", \"arch\": \"{}\", \"relro\": \"{}\", \"nx\": {}, \"pie\": {}, \"canary\": {}, \"needed_libs\": {:?}, \"eh_frame_funcs\": {}}}",
                erep.is_elf, erep.elf_type, erep.machine_arch, erep.relro_mode, erep.nx_enabled, erep.pie_enabled, erep.stack_canary, erep.shared_libraries_needed, erep.eh_frame_functions.len()
            );
        }
        "macho-deep" => {
            let mrep = audit_macho_deep(&data);
            println!(
                "{{\"is_macho\": {}, \"arch\": \"{}\", \"pie\": {}, \"canary\": {}, \"code_signed\": {}, \"dylibs\": {:?}, \"risks\": {:?}}}",
                mrep.is_macho, mrep.architecture, mrep.pie_enabled, mrep.stack_canary, mrep.code_signed, mrep.dylibs, mrep.entitlements_risks
            );
        }
        "pipeline-12" => {
            let prep = run_12_stage_pipeline_rust(&data, path);
            println!(
                "{{\"stages_completed\": {}, \"fnv1a_64\": \"{}\", \"sarif_len\": {}, \"sbom_len\": {}}}",
                prep.stages_completed, prep.fnv1a_64_hash, prep.sarif_v210_json.len(), prep.cyclonedx_v15_sbom_json.len()
            );
        }
        "upx-oep" => {
            let urep = inspect_and_locate_upx_oep(&data, summary.image_base);
            println!(
                "{{\"is_upx\": {}, \"method\": \"{}\", \"oep_va\": {:?}}}",
                urep.is_upx_packed, urep.compression_method, urep.recovered_oep_jmp_va
            );
        }
        "fcn-scan" => {
            let fcns = scan_function_boundaries_rizin(&data, summary.entry_point_va);
            println!("{{\"functions_discovered\": {}}}", fcns.len());
        }
        _ => {
            eprintln!("Unknown command '{}'.", cmd);
            process::exit(1);
        }
    }
}
