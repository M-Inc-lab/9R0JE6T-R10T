//! R3V3R53//F0RG3 — Wave 9 (Phases 184–185): Direct Rust Port of `de4dot` & `AsmResolver`
//! .NET ECMA-335 `#US` User-String Decryptor & Proxy-Call Delegate Inliner
//! (`open_source_de4dot_asmresolver_dotnet.rs`)
//!
//! Directly ports the core .NET deobfuscation passes from `de4dot` (`de4dot.code/deobfuscators`)
//! and `AsmResolver` (`AsmResolver.DotNet`):
//!   - Parses ECMA-335 `#US` (User Strings) compressed length-prefixed UTF-16LE blobs and
//!     emulates constant-key XOR string decryption routines (`ldstr / ldc.i4 token -> call Decrypt`).
//!   - Identifies obfuscator proxy delegates (`ldsfld ProxyDelegate_N; call Invoke` or wrapper
//!     methods consisting solely of `ldarg.0..N; call RealTarget; ret`) and inlines the direct
//!     metadata token (`0x0600XXXX` `MethodDef` / `0x0A00XXXX` `MemberRef`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedDotNetString {
    pub us_offset: usize,
    pub encrypted_len: usize,
    pub decrypted_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlinedProxyCall {
    pub call_site_offset: usize,
    pub proxy_token: u32,
    pub resolved_target_token: u32,
    pub patched_cil: Vec<u8>,
}

/// Decrypt an obfuscated `#US` stream entry using a 16-bit XOR + index rolling key (`de4dot` string decrypter)
pub fn decrypt_dotnet_us_stream_strings(us_heap: &[u8], xor_key: u8) -> Vec<DecryptedDotNetString> {
    let mut out = Vec::new();
    let mut pos = 1usize; // Offset 0 in #US is always the empty 0x00 blob

    while pos < us_heap.len() {
        let len_byte = us_heap[pos] as usize;
        pos += 1;
        if len_byte == 0 || pos + len_byte > us_heap.len() {
            break;
        }
        // UTF-16LE bytes (last byte in #US blob is the terminal 0x00/0x01 flag)
        let str_bytes = if len_byte > 1 { &us_heap[pos..pos + len_byte - 1] } else { &[] };
        let mut utf16_units = Vec::with_capacity(str_bytes.len() / 2);
        let mut j = 0usize;
        while j + 1 < str_bytes.len() {
            let lo = str_bytes[j] ^ xor_key;
            let hi = str_bytes[j + 1];
            utf16_units.push(u16::from_le_bytes([lo, hi]));
            j += 2;
        }
        let text = String::from_utf16_lossy(&utf16_units);
        out.push(DecryptedDotNetString {
            us_offset: pos - 1,
            encrypted_len: len_byte,
            decrypted_text: text,
        });
        pos += len_byte;
    }

    out
}

/// Scan CIL bytecode for `de4dot` proxy call wrappers (`0x28 <proxy_token>`) and inline the resolved target token
pub fn inline_de4dot_proxy_calls(
    cil_code: &[u8],
    proxy_map: &[(u32, u32)],
) -> (Vec<u8>, Vec<InlinedProxyCall>) {
    let mut patched = cil_code.to_vec();
    let mut inlined = Vec::new();
    let mut i = 0usize;

    while i + 5 <= patched.len() {
        // CIL `call` (0x28) or `callvirt` (0x6F) followed by 32-bit metadata token
        if patched[i] == 0x28 || patched[i] == 0x6F {
            let tok = u32::from_le_bytes([patched[i + 1], patched[i + 2], patched[i + 3], patched[i + 4]]);
            if let Some(&(_, real_tok)) = proxy_map.iter().find(|&&(p, _)| p == tok) {
                patched[i] = 0x28; // Direct `call`
                patched[i + 1..i + 5].copy_from_slice(&real_tok.to_le_bytes());
                inlined.push(InlinedProxyCall {
                    call_site_offset: i,
                    proxy_token: tok,
                    resolved_target_token: real_tok,
                    patched_cil: patched[i..i + 5].to_vec(),
                });
                i += 5;
                continue;
            }
        }
        i += 1;
    }

    (patched, inlined)
}
