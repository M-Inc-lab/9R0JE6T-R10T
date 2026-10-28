"""
R3V3R53//F0RG3 — Firebase Cloud Integration & Collaboration Engine (`firebase_sync.py`)
=======================================================================================
Implements verifiable identity-provider authentication, multi-tenant persistence,
and strict boundary enforcement (Phase 4 & Phase 4.1):
  1. Cryptographic Token Verification: Explicit provider algorithm configuration (default RS256),
     algorithm-key compatibility validation (preventing algorithm confusion), strict claim/type
     validation, strict role validation (rejecting unknown roles), server-side tenant membership
     verification, and fail-closed production mode.
  2. Unforgeable Principal Context: `AuthUserContext` carries an HMAC-SHA256 verification seal
     issued exclusively by `FirebaseAuthManager`. Manually constructing `AuthUserContext(..., is_verified=True)`
     or mutating fields after construction invalidates verification immediately.
  3. Hardened Multi-Tenant Persistence: Validates all artifact hashes, tenant IDs, job IDs,
     finding IDs, and blob paths against traversal/URI injection; derives tenant ownership from
     the verified principal; distinguishes NotFound from PermissionDenied and backend outages.
"""

from __future__ import annotations

import abc
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import enum
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# --- Embedded RFC 7519 / RFC 7518 JWT Engine ---
"""
R3V3R53//F0RG3 — Cryptographic RFC 7519 / RFC 7518 JWT Engine (`_jwt_compat.py`)
=================================================================================
Provides a strict RFC 7519 & RFC 7518 compliant JWT implementation backed by
`cryptography` (RSA PKCS#1 v1.5 and ECDSA P-256/P-384/P-521) and `hmac`/`hashlib`
(HMAC-SHA256/384/512) whenever the external `PyJWT` package is not installed in
the Python environment.

Security invariants:
  - Categorically rejects `alg: none` (case-insensitive) and empty algorithms.
  - Enforces strict key-to-algorithm compatibility to prevent algorithm confusion
    (e.g., rejects symmetric HMAC verification when the key is an asymmetric PEM/SSH
    public/private key or X.509 certificate, and rejects RS*/ES* when the key is a
    symmetric secret or mismatched curve/RSA key type).
  - Uses constant-time comparison (`hmac.compare_digest`) for HMAC signatures.
  - Validates `exp`, `nbf`, `iat`, `iss`, `aud`, and `options["require"]` claims with
    strict type checking (rejecting booleans masquerading as ints).
"""


import base64
import hashlib
import hmac
import json
import sys
import time
import types
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    from cryptography.x509 import load_pem_x509_certificate
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


class PyJWTError(Exception):
    """Base exception for all JWT errors."""


class InvalidTokenError(PyJWTError):
    """Base exception when a token fails validation."""


class DecodeError(InvalidTokenError):
    """Raised when a token cannot be decoded structurally or cryptographically."""


class InvalidSignatureError(DecodeError):
    """Raised when signature verification fails."""


class ExpiredSignatureError(InvalidTokenError):
    """Raised when the `exp` claim is in the past."""


class ImmatureSignatureError(InvalidTokenError):
    """Raised when `nbf` or `iat` is in the future."""


class InvalidIssuerError(InvalidTokenError):
    """Raised when the `iss` claim does not match expected issuer."""


class InvalidAudienceError(InvalidTokenError):
    """Raised when the `aud` claim does not match expected audience."""


class InvalidAlgorithmError(InvalidTokenError):
    """Raised when the algorithm is unsupported or not in the allowlist."""


class InvalidKeyError(PyJWTError):
    """Raised when the key is incompatible with the chosen algorithm or malformed."""


class MissingRequiredClaimError(InvalidTokenError):
    """Raised when a required claim is missing from the token payload."""

    def __init__(self, claim: str) -> None:
        super().__init__(f'Token is missing the "{claim}" claim')
        self.claim = claim


_ASYMMETRIC_KEY_MARKERS: Tuple[bytes, ...] = (
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN EC PUBLIC KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN CERTIFICATE-----",
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"ecdsa-sha2-",
)

_HMAC_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_CRYPTO_HASHES = {
    "RS256": "SHA256",
    "RS384": "SHA384",
    "RS512": "SHA512",
    "ES256": "SHA256",
    "ES384": "SHA384",
    "ES512": "SHA512",
}

_EC_COORD_SIZE = {
    "ES256": 32,
    "ES384": 48,
    "ES512": 66,
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str):
        raise DecodeError("Invalid token segment type")
    # Strict URL-safe base64 alphabet check
    for ch in segment:
        if not (ch.isalnum() or ch in "-_="):
            raise DecodeError("Invalid base64url character in token segment")
    rem = len(segment) % 4
    if rem == 1:
        raise DecodeError("Invalid base64url segment length")
    padded = segment + ("=" * ((4 - rem) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise DecodeError(f"Base64 decoding failed: {exc}") from exc


def _is_numeric_timestamp(val: Any) -> bool:
    return not isinstance(val, bool) and isinstance(val, (int, float))


def is_asymmetric_key_material(key: Any) -> bool:
    if _HAS_CRYPTOGRAPHY and isinstance(
        key,
        (
            rsa.RSAPrivateKey,
            rsa.RSAPublicKey,
            ec.EllipticCurvePrivateKey,
            ec.EllipticCurvePublicKey,
        ),
    ):
        return True
    if isinstance(key, str):
        raw = key.strip().encode("utf-8", errors="ignore")
    elif isinstance(key, (bytes, bytearray)):
        raw = bytes(key).strip()
    else:
        return False
    return any(marker in raw for marker in _ASYMMETRIC_KEY_MARKERS)


def _load_public_or_private_key(key: Any, for_signing: bool) -> Any:
    if not _HAS_CRYPTOGRAPHY:
        raise InvalidKeyError("cryptography package is required for asymmetric JWT algorithms")
    if isinstance(
        key,
        (
            rsa.RSAPrivateKey,
            rsa.RSAPublicKey,
            ec.EllipticCurvePrivateKey,
            ec.EllipticCurvePublicKey,
        ),
    ):
        return key
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
    else:
        raise InvalidKeyError("Unsupported key type for asymmetric algorithm")

    if b"\x00" in key_bytes:
        raise InvalidKeyError("Key contains null bytes")

    try:
        if for_signing:
            return serialization.load_pem_private_key(key_bytes, password=None)
        if b"-----BEGIN CERTIFICATE-----" in key_bytes:
            cert = load_pem_x509_certificate(key_bytes)
            return cert.public_key()
        if b"PRIVATE KEY-----" in key_bytes:
            priv = serialization.load_pem_private_key(key_bytes, password=None)
            return priv.public_key()
        return serialization.load_pem_public_key(key_bytes)
    except Exception as exc:
        raise InvalidKeyError(f"Failed to parse PEM key material: {exc}") from exc


def validate_key_algorithm_compatibility(key: Any, algorithm: str, for_signing: bool = False) -> None:
    """Ensure the provided key is strictly compatible with the JWT algorithm."""
    if not isinstance(algorithm, str) or not algorithm:
        raise InvalidAlgorithmError("Algorithm must be a non-empty string")
    alg = algorithm.upper()
    if alg == "NONE":
        raise InvalidAlgorithmError("The 'none' algorithm is forbidden")

    if alg in _HMAC_HASHES:
        if key is None:
            raise InvalidKeyError("Symmetric HMAC key cannot be None")
        if is_asymmetric_key_material(key):
            raise InvalidKeyError(
                f"Algorithm confusion blocked: asymmetric key material cannot be used with {alg}"
            )
        if not isinstance(key, (str, bytes, bytearray)):
            raise InvalidKeyError(f"HMAC key must be str or bytes, got {type(key).__name__}")
        raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        if not raw:
            raise InvalidKeyError("HMAC key cannot be empty")
        return

    if alg.startswith("RS"):
        if alg not in _CRYPTO_HASHES:
            raise InvalidAlgorithmError(f"Unsupported RSA algorithm: {alg}")
        parsed = _load_public_or_private_key(key, for_signing=for_signing)
        if for_signing and not isinstance(parsed, rsa.RSAPrivateKey):
            raise InvalidKeyError(f"{alg} signing requires an RSA private key")
        if not for_signing and not isinstance(parsed, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
            raise InvalidKeyError(f"{alg} verification requires an RSA key")
        return

    if alg.startswith("ES"):
        if alg not in _CRYPTO_HASHES:
            raise InvalidAlgorithmError(f"Unsupported ECDSA algorithm: {alg}")
        parsed = _load_public_or_private_key(key, for_signing=for_signing)
        if for_signing and not isinstance(parsed, ec.EllipticCurvePrivateKey):
            raise InvalidKeyError(f"{alg} signing requires an EC private key")
        if not for_signing and not isinstance(parsed, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
            raise InvalidKeyError(f"{alg} verification requires an EC key")
        return

    raise InvalidAlgorithmError(f"Unsupported algorithm: {algorithm}")


def get_unverified_header(token: Union[str, bytes]) -> Dict[str, Any]:
    if isinstance(token, bytes):
        try:
            token = token.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("Invalid token encoding") from exc
    if not isinstance(token, str):
        raise DecodeError("Token must be a string")
    parts = token.split(".")
    if len(parts) != 3 or not parts[0]:
        raise DecodeError("Not enough segments")
    raw_hdr = _b64url_decode(parts[0])
    try:
        hdr = json.loads(raw_hdr.decode("utf-8"))
    except Exception as exc:
        raise DecodeError(f"Invalid header JSON: {exc}") from exc
    if not isinstance(hdr, dict):
        raise DecodeError("JWT header must be a JSON object")
    return hdr


def encode(
    payload: Dict[str, Any],
    key: Any,
    algorithm: str = "HS256",
    headers: Optional[Dict[str, Any]] = None,
) -> str:
    if not isinstance(payload, dict):
        raise TypeError("Payload must be a dict")
    validate_key_algorithm_compatibility(key, algorithm, for_signing=True)
    alg = algorithm.upper()

    hdr: Dict[str, Any] = {"typ": "JWT", "alg": alg}
    if headers:
        hdr.update(headers)
        hdr["alg"] = alg

    header_b64 = _b64url_encode(
        json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if alg in _HMAC_HASHES:
        key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        sig = hmac.new(key_bytes, signing_input, _HMAC_HASHES[alg]).digest()
    elif alg.startswith("RS"):
        priv_key = _load_public_or_private_key(key, for_signing=True)
        hash_cls = getattr(hashes, _CRYPTO_HASHES[alg])
        sig = priv_key.sign(signing_input, padding.PKCS1v15(), hash_cls())
    elif alg.startswith("ES"):
        priv_key = _load_public_or_private_key(key, for_signing=True)
        hash_cls = getattr(hashes, _CRYPTO_HASHES[alg])
        der_sig = priv_key.sign(signing_input, ec.ECDSA(hash_cls()))
        r, s = utils.decode_dss_signature(der_sig)
        coord_size = _EC_COORD_SIZE[alg]
        sig = r.to_bytes(coord_size, "big") + s.to_bytes(coord_size, "big")
    else:  # pragma: no cover
        raise InvalidAlgorithmError(f"Unsupported algorithm: {alg}")

    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def decode(
    jwt_token: Union[str, bytes],
    key: Any = "",
    algorithms: Optional[Sequence[str]] = None,
    options: Optional[Dict[str, Any]] = None,
    audience: Optional[Union[str, Iterable[str]]] = None,
    issuer: Optional[Union[str, Sequence[str]]] = None,
    leeway: float = 0.0,
) -> Dict[str, Any]:
    if isinstance(jwt_token, bytes):
        try:
            jwt_token = jwt_token.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("Invalid token encoding") from exc
    if not isinstance(jwt_token, str):
        raise DecodeError("Expected string or bytes token")

    parts = jwt_token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise DecodeError("Not enough segments")

    header_b64, payload_b64, crypto_b64 = parts
    raw_header = _b64url_decode(header_b64)
    try:
        header = json.loads(raw_header.decode("utf-8"))
    except Exception as exc:
        raise DecodeError(f"Invalid header string: {exc}") from exc
    if not isinstance(header, dict):
        raise DecodeError("Invalid header: must be a JSON object")

    opts = dict(options or {})
    verify_signature = opts.get("verify_signature", True)

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg or alg.upper() == "NONE":
        raise InvalidAlgorithmError("The specified alg value is not allowed")

    if verify_signature:
        if not algorithms:
            raise DecodeError('It is required that you pass in a value for the "algorithms" argument')
        allowed_upper = [a.upper() for a in algorithms if isinstance(a, str)]
        if alg.upper() not in allowed_upper or "NONE" in allowed_upper:
            raise InvalidAlgorithmError(f"The specified alg value '{alg}' is not allowed")

        validate_key_algorithm_compatibility(key, alg, for_signing=False)
        if not crypto_b64:
            raise InvalidSignatureError("Signature segment is empty")
        signature = _b64url_decode(crypto_b64)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        alg_u = alg.upper()
        if alg_u in _HMAC_HASHES:
            key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
            expected = hmac.new(key_bytes, signing_input, _HMAC_HASHES[alg_u]).digest()
            if not hmac.compare_digest(signature, expected):
                raise InvalidSignatureError("Signature verification failed")
        elif alg_u.startswith("RS"):
            pub_key = _load_public_or_private_key(key, for_signing=False)
            if isinstance(pub_key, rsa.RSAPrivateKey):
                pub_key = pub_key.public_key()
            hash_cls = getattr(hashes, _CRYPTO_HASHES[alg_u])
            try:
                pub_key.verify(signature, signing_input, padding.PKCS1v15(), hash_cls())
            except Exception as exc:
                raise InvalidSignatureError("RSA signature verification failed") from exc
        elif alg_u.startswith("ES"):
            pub_key = _load_public_or_private_key(key, for_signing=False)
            if isinstance(pub_key, ec.EllipticCurvePrivateKey):
                pub_key = pub_key.public_key()
            hash_cls = getattr(hashes, _CRYPTO_HASHES[alg_u])
            coord_size = _EC_COORD_SIZE[alg_u]
            try:
                if len(signature) == coord_size * 2:
                    r = int.from_bytes(signature[:coord_size], "big")
                    s = int.from_bytes(signature[coord_size:], "big")
                    der_sig = utils.encode_dss_signature(r, s)
                else:
                    der_sig = signature
                pub_key.verify(der_sig, signing_input, ec.ECDSA(hash_cls()))
            except Exception as exc:
                raise InvalidSignatureError("ECDSA signature verification failed") from exc

    raw_payload = _b64url_decode(payload_b64)
    try:
        payload = json.loads(raw_payload.decode("utf-8"))
    except Exception as exc:
        raise DecodeError(f"Invalid payload string: {exc}") from exc
    if not isinstance(payload, dict):
        raise DecodeError("Invalid payload: must be a JSON object")

    required_claims = opts.get("require", [])
    for req_claim in required_claims:
        if req_claim not in payload or payload[req_claim] is None:
            raise MissingRequiredClaimError(req_claim)

    now = time.time()
    skew = float(leeway or 0.0)

    if opts.get("verify_exp", True) and "exp" in payload:
        exp_val = payload["exp"]
        if not _is_numeric_timestamp(exp_val):
            raise DecodeError("Expiration Time claim (exp) must be an integer or float")
        if now > (float(exp_val) + skew):
            raise ExpiredSignatureError("Signature has expired")

    if opts.get("verify_nbf", True) and "nbf" in payload:
        nbf_val = payload["nbf"]
        if not _is_numeric_timestamp(nbf_val):
            raise DecodeError("Not Before claim (nbf) must be an integer or float")
        if now < (float(nbf_val) - skew):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    if opts.get("verify_iat", True) and "iat" in payload:
        iat_val = payload["iat"]
        if not _is_numeric_timestamp(iat_val):
            raise DecodeError("Issued At claim (iat) must be an integer or float")

    if opts.get("verify_iss", True) and issuer is not None:
        tok_iss = payload.get("iss")
        if not isinstance(tok_iss, str):
            raise InvalidIssuerError("Invalid issuer")
        if isinstance(issuer, str):
            if tok_iss != issuer:
                raise InvalidIssuerError("Invalid issuer")
        else:
            if tok_iss not in issuer:
                raise InvalidIssuerError("Invalid issuer")

    if opts.get("verify_aud", True) and audience is not None:
        if "aud" not in payload:
            raise InvalidAudienceError("Missing audience claim")
        tok_aud = payload["aud"]
        if isinstance(tok_aud, str):
            aud_list = [tok_aud]
        elif isinstance(tok_aud, list) and all(isinstance(x, str) for x in tok_aud) and len(tok_aud) > 0:
            aud_list = tok_aud
        else:
            raise InvalidAudienceError("Invalid audience claim format")

        expected_auds = [audience] if isinstance(audience, str) else list(audience)
        if not any(a in expected_auds for a in aud_list):
            raise InvalidAudienceError("Audience doesn't match")

    return payload


def ensure_jwt_module() -> Any:
    """Return the installed `jwt` module or register this RFC 7519 engine in `sys.modules['jwt']`."""
    existing = sys.modules.get("jwt")
    if existing is not None and hasattr(existing, "encode") and hasattr(existing, "decode"):
        return existing
    try:
        import jwt as external_jwt  # type: ignore[import-not-found]
        return external_jwt
    except ImportError:
        mod = types.ModuleType("jwt")
        mod.__doc__ = __doc__
        mod.PyJWTError = PyJWTError  # type: ignore[attr-defined]
        mod.InvalidTokenError = InvalidTokenError  # type: ignore[attr-defined]
        mod.DecodeError = DecodeError  # type: ignore[attr-defined]
        mod.InvalidSignatureError = InvalidSignatureError  # type: ignore[attr-defined]
        mod.ExpiredSignatureError = ExpiredSignatureError  # type: ignore[attr-defined]
        mod.ImmatureSignatureError = ImmatureSignatureError  # type: ignore[attr-defined]
        mod.InvalidIssuerError = InvalidIssuerError  # type: ignore[attr-defined]
        mod.InvalidAudienceError = InvalidAudienceError  # type: ignore[attr-defined]
        mod.InvalidAlgorithmError = InvalidAlgorithmError  # type: ignore[attr-defined]
        mod.InvalidKeyError = InvalidKeyError  # type: ignore[attr-defined]
        mod.MissingRequiredClaimError = MissingRequiredClaimError  # type: ignore[attr-defined]
        mod.encode = encode  # type: ignore[attr-defined]
        mod.decode = decode  # type: ignore[attr-defined]
        mod.get_unverified_header = get_unverified_header  # type: ignore[attr-defined]
        mod.is_asymmetric_key_material = is_asymmetric_key_material  # type: ignore[attr-defined]
        mod.validate_key_algorithm_compatibility = validate_key_algorithm_compatibility  # type: ignore[attr-defined]
        mod._is_builtin_rf_jwt = True  # type: ignore[attr-defined]

        exceptions_mod = types.ModuleType("jwt.exceptions")
        for attr in (
            "PyJWTError",
            "InvalidTokenError",
            "DecodeError",
            "InvalidSignatureError",
            "ExpiredSignatureError",
            "ImmatureSignatureError",
            "InvalidIssuerError",
            "InvalidAudienceError",
            "InvalidAlgorithmError",
            "InvalidKeyError",
            "MissingRequiredClaimError",
        ):
            setattr(exceptions_mod, attr, getattr(mod, attr))
        mod.exceptions = exceptions_mod  # type: ignore[attr-defined]
        sys.modules["jwt"] = mod
        sys.modules["jwt.exceptions"] = exceptions_mod
        return mod

# --- End Embedded JWT Engine ---

jwt = ensure_jwt_module()

try:
    from google.cloud import firestore, storage
    from google.oauth2 import service_account
except ImportError:
    firestore = None
    storage = None
    service_account = None

logger = logging.getLogger("reverse_forge.firebase_sync")

# Module-private CSPRNG secret used to seal cryptographically verified AuthUserContext instances.
# External callers cannot forge this seal merely by passing is_verified=True to AuthUserContext().
_AUTH_CONTEXT_SEAL_KEY: bytes = os.urandom(32)

_SAFE_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SAFE_DOC_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SAFE_SHA256_RE = re.compile(r"^[0-9a-fA-F]{60,64}$")
_SAFE_PATH_SEG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SUPPORTED_JWT_ALGORITHMS: Set[str] = {
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "HS256", "HS384", "HS512",
}


class PersistenceError(RuntimeError):
    """Base error for persistence layer failures."""


class PersistencePermissionError(PermissionError):
    """Raised when a persistence operation is denied due to permissions or tenant mismatch."""


class PersistenceUnavailableError(PersistenceError):
    """Raised when the persistence backend encounters a network, configuration, or service outage."""


def validate_tenant_id(tenant_id: Any) -> str:
    """Validate that a tenant identifier is a safe, canonical string."""
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("Invalid tenant_id: must be a non-empty string")
    if "\x00" in tenant_id or ".." in tenant_id or "/" in tenant_id or "\\" in tenant_id:
        raise ValueError(f"Invalid tenant_id (path traversal or separator rejected): {tenant_id!r}")
    if not _SAFE_TENANT_RE.match(tenant_id):
        raise ValueError(f"Invalid tenant_id format: {tenant_id!r}")
    return tenant_id


def validate_artifact_sha256(sha256: Any) -> str:
    """Validate that an artifact identifier is a safe hexadecimal digest."""
    if not isinstance(sha256, str) or not sha256:
        raise ValueError("Invalid artifact sha256: must be a non-empty hex string")
    if "\x00" in sha256 or ".." in sha256 or "/" in sha256 or "\\" in sha256 or ":" in sha256:
        raise ValueError("Invalid artifact sha256: forbidden path characters")
    if not _SAFE_SHA256_RE.match(sha256):
        raise ValueError(f"Invalid artifact sha256 format: {sha256!r}")
    return sha256.lower()


def validate_document_id(doc_id: Any, label: str = "document_id") -> str:
    """Validate a Firestore document identifier (e.g. job_id, finding_id)."""
    if not isinstance(doc_id, str) or not doc_id:
        raise ValueError(f"Invalid {label}: must be a non-empty string")
    if doc_id in (".", "..") or ".." in doc_id or "/" in doc_id or "\\" in doc_id or "\x00" in doc_id or ":" in doc_id:
        raise ValueError(f"Invalid {label} (path traversal or separator rejected): {doc_id!r}")
    if not _SAFE_DOC_ID_RE.match(doc_id):
        raise ValueError(f"Invalid {label} format: {doc_id!r}")
    return doc_id


def validate_storage_blob_path(path: Any) -> str:
    """
    Validate a relative blob object path.
    Rejects URI schemes, path traversal ('..'), leading/trailing/duplicate slashes, backslashes, and null bytes.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Invalid storage blob path: must be a non-empty string")
    if "\x00" in path or "\\" in path or "://" in path or path.startswith(("gs:", "http:", "https:", "file:", "local-sim:")):
        raise ValueError(f"Invalid storage blob path (forbidden scheme or separator): {path!r}")
    if path.startswith("/") or path.endswith("/") or "//" in path:
        raise ValueError(f"Invalid storage blob path (ambiguous leading/trailing/duplicate slash): {path!r}")
    segments = path.split("/")
    for seg in segments:
        if not seg or seg in (".", "..") or ".." in seg or not _SAFE_PATH_SEG_RE.match(seg):
            raise ValueError(f"Invalid storage blob path segment {seg!r} in {path!r}")
    return "/".join(segments)


class UserRole(enum.Enum):
    VIEWER = "VIEWER"                    # Read-only access to reports and disassembly
    ANALYST = "ANALYST"                  # Can annotate, decompile, and submit analysis jobs
    LEAD_ARCHITECT = "LEAD_ARCHITECT"    # Full control including policy, deletion, and exports


def _compute_context_seal(uid: str, email: str, role: UserRole, tenant_id: str) -> str:
    msg = f"rf_auth_seal_v1|{uid}|{email}|{role.value}|{tenant_id}".encode("utf-8")
    return hmac.new(_AUTH_CONTEXT_SEAL_KEY, msg, hashlib.sha256).hexdigest()


def _create_sealed_user_context(
    uid: str,
    email: str,
    role: UserRole = UserRole.ANALYST,
    tenant_id: str = "default_tenant",
    token_claims: Optional[Dict[str, Any]] = None,
) -> AuthUserContext:
    """Internal authority helper to construct a cryptographically sealed AuthUserContext."""
    validate_tenant_id(tenant_id)
    if not isinstance(role, UserRole):
        raise ValueError(f"Invalid UserRole: {role!r}")
    if not isinstance(uid, str) or not uid.strip():
        raise ValueError("uid must be a non-empty string")
    if not isinstance(email, str) or not email.strip():
        raise ValueError("email must be a non-empty string")
    seal = _compute_context_seal(uid, email, role, tenant_id)
    return AuthUserContext(
        uid=uid,
        email=email,
        role=role,
        tenant_id=tenant_id,
        token_claims=dict(token_claims or {}),
        is_verified=True,
        _verification_seal=seal,
    )


@dataclass
class AuthUserContext:
    """
    Principal security context.
    Note: Setting `is_verified=True` directly via `AuthUserContext(...)` without a valid
    cryptographic `_verification_seal` issued by `FirebaseAuthManager` is automatically
    downgraded to `is_verified=False` and rejected by all authorization boundaries.
    """
    uid: str
    email: str
    role: UserRole = UserRole.ANALYST
    tenant_id: str = "default_tenant"
    token_claims: Dict[str, Any] = field(default_factory=dict)
    is_verified: bool = False
    _verification_seal: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.role, UserRole):
            raise ValueError(f"Invalid role type: expected UserRole, got {self.role!r}")
        if self.is_verified:
            if not self._has_valid_seal():
                # Direct construction with is_verified=True without authority seal is downgraded
                object.__setattr__(self, "is_verified", False)
                object.__setattr__(self, "_verification_seal", "")

    def _has_valid_seal(self) -> bool:
        if not isinstance(self._verification_seal, str) or not self._verification_seal:
            return False
        if not isinstance(self.uid, str) or not self.uid or not isinstance(self.email, str):
            return False
        if not isinstance(self.role, UserRole) or not isinstance(self.tenant_id, str) or not self.tenant_id:
            return False
        expected = _compute_context_seal(self.uid, self.email, self.role, self.tenant_id)
        return hmac.compare_digest(self._verification_seal, expected)

    def is_cryptographically_verified(self) -> bool:
        """Returns True iff is_verified is True AND the HMAC verification seal matches all identity fields."""
        return bool(self.is_verified and self._has_valid_seal())

    def can_modify(self) -> bool:
        return self.is_cryptographically_verified() and self.role in (UserRole.ANALYST, UserRole.LEAD_ARCHITECT)

    def is_lead(self) -> bool:
        return self.is_cryptographically_verified() and self.role == UserRole.LEAD_ARCHITECT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uid": self.uid,
            "email": self.email,
            "role": self.role.value if isinstance(self.role, UserRole) else str(self.role),
            "tenant_id": self.tenant_id,
            "token_claims": self.token_claims,
            "is_verified": self.is_cryptographically_verified(),
        }


@dataclass
class FirestoreArtifactDocument:
    """Document schema for collection `tenants/{tenant_id}/artifacts/{sha256}`."""
    sha256: str
    filename: str
    size_bytes: int
    format_name: str
    architecture: str
    entropy: float
    overall_posture: str
    uploaded_by: str
    tenant_id: str
    created_at: str
    storage_path: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings_count: int = 0
    capabilities_count: int = 0


@dataclass
class FirestoreFindingDocument:
    """Document schema for subcollection `tenants/{tenant_id}/artifacts/{sha256}/findings/{finding_id}`."""
    finding_id: str
    cwe_id: str
    title: str
    severity: str
    cvss_score: float
    location_va: str
    sink_or_section: str
    evidence: str
    remediation: str
    detected_at: str
    tenant_id: str = "default_tenant"


@dataclass
class FirestoreJobDocument:
    """Document schema for collection `tenants/{tenant_id}/jobs/{job_id}`."""
    job_id: str
    artifact_sha256: str
    job_type: str
    status: str  # QUEUED, RUNNING, COMPLETED, FAILED
    progress_pct: int
    current_stage: str
    submitted_by: str
    tenant_id: str
    created_at: str
    updated_at: str
    error: Optional[str] = None
    result_summary: Dict[str, Any] = field(default_factory=dict)


# ==============================================================================
# SECTION 1: REVOCATION STORE & IDENTITY PROVIDER VERIFICATION ENGINE
# ==============================================================================

class SharedRevocationStore:
    """
    Atomic SQLite-backed revocation store for sharing token/user revocations across
    worker processes and preserving revocation state across restarts.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS revoked_identities ("
                    "kind TEXT NOT NULL, "
                    "identifier TEXT NOT NULL, "
                    "revoked_at REAL NOT NULL, "
                    "PRIMARY KEY (kind, identifier))"
                )
                conn.commit()
            finally:
                conn.close()

    def add_revocation(self, kind: str, identifier: str) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO revoked_identities (kind, identifier, revoked_at) VALUES (?, ?, ?)",
                    (kind, identifier, time.time()),
                )
                conn.commit()
            finally:
                conn.close()

    def is_revoked(self, kind: str, identifier: str) -> bool:
        if not identifier:
            return False
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            try:
                cur = conn.execute(
                    "SELECT 1 FROM revoked_identities WHERE kind = ? AND identifier = ? LIMIT 1",
                    (kind, identifier),
                )
                return cur.fetchone() is not None
            finally:
                conn.close()


class FirebaseAuthManager:
    """
    Handles identity-provider cryptographic token validation, JWT decoding,
    revocation checking, server-side tenant membership verification, and RBAC
    authorization with fail-closed security.

    Revocation Architecture:
      - By default, `revoked_tokens` and `revoked_users` are maintained in process-local sets
        per `FirebaseAuthManager` instance.
      - When `revocation_store` (or `FIREBASE_REVOCATION_DB_PATH`) is provided, revocations are
        persisted and checked through `SharedRevocationStore` (SQLite WAL) across workers and restarts.
    """

    DEFAULT_CLOCK_SKEW_SECONDS: float = 5.0

    def __init__(
        self,
        project_id: Optional[str] = None,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        verification_key: Optional[Any] = None,
        allowed_algorithms: Optional[List[str]] = None,
        allow_dev_mock: bool = False,
        trusted_tenants: Optional[Set[str]] = None,
        tenant_membership_policy: Optional[Dict[str, Set[str]]] = None,
        user_role_bindings: Optional[Dict[str, UserRole]] = None,
        revocation_store: Optional[SharedRevocationStore] = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ):
        self.project_id = project_id or os.environ.get("FIREBASE_PROJECT_ID", "reverse-forge-local")
        self.expected_issuer = expected_issuer or os.environ.get(
            "FIREBASE_EXPECTED_ISSUER", f"https://securetoken.google.com/{self.project_id}"
        )
        self.expected_audience = expected_audience or os.environ.get(
            "FIREBASE_EXPECTED_AUDIENCE", self.project_id
        )
        self.verification_key = (
            verification_key
            if verification_key is not None
            else os.environ.get("FIREBASE_JWT_VERIFICATION_KEY")
        )
        # Default explicitly to RS256 (Google/Firebase Identity Provider standard) rather than a broad list
        if allowed_algorithms is None:
            env_algs = os.environ.get("FIREBASE_ALLOWED_ALGORITHMS", "").strip()
            if env_algs:
                self.allowed_algorithms = [a.strip().upper() for a in env_algs.split(",") if a.strip()]
            else:
                self.allowed_algorithms = ["RS256"]
        else:
            self.allowed_algorithms = [str(a).strip().upper() for a in allowed_algorithms if str(a).strip()]

        self.allow_dev_mock = bool(allow_dev_mock)

        if trusted_tenants is not None:
            self.trusted_tenants: Optional[Set[str]] = set(trusted_tenants)
        else:
            env_tenants = os.environ.get("FIREBASE_TRUSTED_TENANTS", "").strip()
            self.trusted_tenants = (
                {t.strip() for t in env_tenants.split(",") if t.strip()} if env_tenants else None
            )

        self.tenant_membership_policy: Optional[Dict[str, Set[str]]] = (
            {k: set(v) for k, v in tenant_membership_policy.items()}
            if tenant_membership_policy is not None
            else None
        )
        self.user_role_bindings: Dict[str, UserRole] = dict(user_role_bindings or {})
        self.clock_skew_seconds = max(0.0, float(clock_skew_seconds))

        # Process-local revocation denylists + optional shared persistent store
        self.revoked_tokens: Set[str] = set()
        self.revoked_users: Set[str] = set()
        rev_db_path = os.environ.get("FIREBASE_REVOCATION_DB_PATH", "").strip()
        self.revocation_store: Optional[SharedRevocationStore] = revocation_store or (
            SharedRevocationStore(rev_db_path) if rev_db_path else None
        )

        env_mode = os.environ.get("REVERSE_FORGE_ENV", "").strip().lower()
        self.is_production = env_mode == "production"
        has_key = bool(os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY") or self.verification_key)

        if self.is_production and not has_key:
            logger.error("PRODUCTION CONFIGURATION ERROR: No trusted key or service account configured in production mode!")
            self.mock_mode = False
        else:
            self.mock_mode = (not has_key) and self.allow_dev_mock and (not self.is_production)

    @property
    def revocation_persistence_mode(self) -> str:
        """Explicitly reports whether revocation state is 'shared_sqlite' or 'process_local'."""
        return "shared_sqlite" if self.revocation_store is not None else "process_local"

    def revoke_token(self, token_or_jti: str) -> None:
        """Add a token or JTI to the revocation denylist."""
        if not isinstance(token_or_jti, str) or not token_or_jti:
            return
        self.revoked_tokens.add(token_or_jti)
        if self.revocation_store is not None:
            self.revocation_store.add_revocation("token", token_or_jti)

    def revoke_user(self, uid: str) -> None:
        """Revoke all sessions for a specific user ID."""
        if not isinstance(uid, str) or not uid:
            return
        self.revoked_users.add(uid)
        if self.revocation_store is not None:
            self.revocation_store.add_revocation("user", uid)

    def is_token_or_user_revoked(self, token: str, jti: str, uid: str) -> bool:
        if token in self.revoked_tokens or (jti and jti in self.revoked_tokens) or (uid and uid in self.revoked_users):
            return True
        if self.revocation_store is not None:
            if self.revocation_store.is_revoked("token", token):
                return True
            if jti and self.revocation_store.is_revoked("token", jti):
                return True
            if uid and self.revocation_store.is_revoked("user", uid):
                return True
        return False

    @staticmethod
    def resolve_role(role_claim: Any) -> UserRole:
        """
        Strictly resolve a role claim to a `UserRole` enum member.
        Raises ValueError on any unknown, malformed, or non-string role value.
        Never converts an unrecognized role into a privileged default.
        """
        if not isinstance(role_claim, str) or not role_claim.strip():
            raise ValueError(f"Malformed role claim: expected non-empty string, got {role_claim!r}")
        normalized = role_claim.strip().upper()
        try:
            return UserRole[normalized]
        except KeyError as exc:
            raise ValueError(f"Unknown or unauthorized role value: {role_claim!r}") from exc

    def issue_verified_context(
        self,
        uid: str,
        email: str,
        role: UserRole = UserRole.ANALYST,
        tenant_id: str = "default_tenant",
        token_claims: Optional[Dict[str, Any]] = None,
    ) -> AuthUserContext:
        """
        Explicit authority method on FirebaseAuthManager to issue a sealed, verified AuthUserContext
        after server-side verification (or for controlled test fixtures).
        """
        if self.is_production and not self.verification_key:
            raise PermissionError("Cannot issue verified context in production without configured verification_key")
        if self.is_token_or_user_revoked("", "", uid):
            raise PermissionError(f"Cannot issue verified context for revoked user '{uid}'")
        if self.trusted_tenants is not None and tenant_id not in self.trusted_tenants:
            raise PermissionError(f"Tenant '{tenant_id}' is not in trusted_tenants")
        if self.tenant_membership_policy is not None:
            allowed_for_uid = self.tenant_membership_policy.get(uid) or self.tenant_membership_policy.get("*", set())
            if tenant_id not in allowed_for_uid:
                raise PermissionError(f"Principal '{uid}' is not a member of tenant '{tenant_id}'")
        return _create_sealed_user_context(
            uid=uid,
            email=email,
            role=role,
            tenant_id=tenant_id,
            token_claims=token_claims,
        )

    def _validate_tenant_membership(self, uid: str, claims: Dict[str, Any]) -> Optional[str]:
        """
        Validate tenant membership against server-side policy and trusted tenants.
        A tenant claim in a token cannot independently establish access to an untrusted tenant.
        """
        raw_tenant = claims.get("tenant_id")
        firebase_claim = claims.get("firebase")
        if raw_tenant is None and isinstance(firebase_claim, dict):
            raw_tenant = firebase_claim.get("tenant")

        if raw_tenant is not None:
            if not isinstance(raw_tenant, str):
                logger.warning("Token verification failed: non-string tenant_id claim")
                return None
            try:
                tenant_id = validate_tenant_id(raw_tenant)
            except ValueError as err:
                logger.warning("Token verification failed: %s", err)
                return None
        else:
            if self.is_production:
                logger.warning("Token verification failed: missing tenant_id claim in production")
                return None
            tenant_id = "default_tenant"

        # Check server-side uid -> tenant membership policy when configured
        if self.tenant_membership_policy is not None:
            allowed_for_user = self.tenant_membership_policy.get(uid)
            if allowed_for_user is None:
                allowed_for_user = self.tenant_membership_policy.get("*")
            if not allowed_for_user or tenant_id not in allowed_for_user:
                logger.warning(
                    "Token verification failed: principal '%s' is not authorized for tenant '%s'",
                    uid,
                    tenant_id,
                )
                return None

        # Check trusted_tenants allowlist when configured
        if self.trusted_tenants is not None and tenant_id not in self.trusted_tenants:
            logger.warning("Token verification failed: unauthorized or fabricated tenant_id '%s'", tenant_id)
            return None

        return tenant_id

    def verify_bearer_token(self, auth_header: Optional[str]) -> Optional[AuthUserContext]:
        """
        Verify the HTTP Authorization: Bearer <token> header.
        Enforces cryptographic signature verification, algorithm-key compatibility,
        expiration, audience/issuer checks, revocation checks, strict role validation,
        and server-side tenant authorization.
        """
        # 1. Missing Authorization Header handling
        if not auth_header or not isinstance(auth_header, str):
            if self.is_production or not self.allow_dev_mock:
                return None
            return AuthUserContext(
                uid="dev_local_user",
                email="architect@reverse-forge.local",
                role=UserRole.VIEWER,
                tenant_id="local_lab",
                is_verified=False,
            )

        if "\x00" in auth_header or "\r" in auth_header or "\n" in auth_header:
            return None

        parts = auth_header.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None

        token = parts[1].strip()
        if not token:
            return None

        # 2. Mock token check (strictly local-only, explicitly enabled, unverified, VIEWER role)
        if token.startswith("mock-token-") or token.startswith("dev-token-"):
            if self.is_production:
                logger.error("SECURITY ALERT: Mock token presented in production environment!")
                return None
            if not self.allow_dev_mock:
                logger.warning("Mock token rejected: allow_dev_mock is disabled")
                return None
            return AuthUserContext(
                uid=token,
                email="dev@reverse-forge.local",
                role=UserRole.VIEWER,
                tenant_id="local_lab",
                is_verified=False,
            )

        # 3. Real JWT format inspection: must be 3-part signed JWT with non-empty signature
        jwt_parts = token.split(".")
        if len(jwt_parts) != 3 or not jwt_parts[0] or not jwt_parts[1] or not jwt_parts[2]:
            logger.warning("Rejecting malformed token structure (expected 3 non-empty parts)")
            return None

        # 4. Check header algorithm and key compatibility: never allow 'none' or mismatched key types
        if not self.allowed_algorithms:
            logger.warning("Rejecting token: allowed_algorithms is empty")
            return None

        try:
            hdr_rem = len(jwt_parts[0]) % 4
            if hdr_rem == 1:
                return None
            hdr_raw = jwt_parts[0] + "=" * ((4 - hdr_rem) % 4)
            hdr = json.loads(base64.urlsafe_b64decode(hdr_raw.encode("ascii")).decode("utf-8"))
            if not isinstance(hdr, dict):
                return None
            raw_alg = hdr.get("alg")
            if not isinstance(raw_alg, str) or not raw_alg:
                return None
            alg = raw_alg.upper()
            if alg == "NONE" or alg not in _SUPPORTED_JWT_ALGORITHMS or alg not in self.allowed_algorithms:
                logger.warning("Rejecting insecure or unsupported algorithm: %s", alg)
                return None
        except Exception as e:
            logger.warning("Failed to decode token header: %s", e)
            return None

        # 5. Cryptographic Signature & Key Compatibility Verification
        if not self.verification_key or jwt is None:
            logger.warning("Production/secure token rejected: No trusted verification key available")
            return None

        if not self.expected_issuer or not self.expected_audience:
            logger.warning("Token rejected: incomplete issuer or audience configuration")
            return None

        try:
            validate_key_algorithm_compatibility(self.verification_key, alg, for_signing=False)
            claims = jwt.decode(
                token,
                self.verification_key,
                algorithms=[alg],
                audience=self.expected_audience,
                issuer=self.expected_issuer,
                leeway=self.clock_skew_seconds,
                options={
                    "require": ["exp", "sub", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except Exception as err:
            logger.warning("Token verification failed: %s", type(err).__name__)
            return None

        if not isinstance(claims, dict):
            return None

        # 6. Strict Claim Type & Value Validation
        uid = claims.get("sub")
        if not isinstance(uid, str) or not uid.strip() or len(uid) > 128 or "\x00" in uid or uid.strip().lower() == "anonymous":
            logger.warning("Token verification failed: invalid 'sub' claim")
            return None

        exp_val = claims.get("exp")
        if isinstance(exp_val, bool) or not isinstance(exp_val, (int, float)):
            logger.warning("Token verification failed: non-numeric 'exp' claim")
            return None

        if "nbf" in claims:
            nbf_val = claims.get("nbf")
            if isinstance(nbf_val, bool) or not isinstance(nbf_val, (int, float)):
                logger.warning("Token verification failed: non-numeric 'nbf' claim")
                return None

        if "iat" in claims:
            iat_val = claims.get("iat")
            if isinstance(iat_val, bool) or not isinstance(iat_val, (int, float)):
                logger.warning("Token verification failed: non-numeric 'iat' claim")
                return None
            if float(iat_val) > (time.time() + self.clock_skew_seconds):
                logger.warning("Token verification failed: future-issued 'iat' claim")
                return None

        if "jti" in claims:
            jti_val = claims.get("jti")
            if not isinstance(jti_val, str) or not jti_val.strip() or "\x00" in jti_val:
                logger.warning("Token verification failed: invalid 'jti' claim")
                return None
            jti_str = jti_val.strip()
        else:
            jti_str = ""

        email = claims.get("email", "operator@reverse-forge.cloud")
        if not isinstance(email, str) or not email.strip() or "\x00" in email:
            logger.warning("Token verification failed: invalid 'email' claim")
            return None

        # 7. Revocation checks (process-local and optional shared store)
        if self.is_token_or_user_revoked(token, jti_str, uid):
            logger.warning("Token verification failed: token or user is revoked")
            return None

        # 8. Server-side Tenant Membership Validation
        tenant_id = self._validate_tenant_membership(uid, claims)
        if tenant_id is None:
            return None

        # 9. Strict Role Validation (never convert unknown role to privileged default)
        if uid in self.user_role_bindings:
            role = self.user_role_bindings[uid]
            if "role" in claims:
                try:
                    claimed_role = self.resolve_role(claims["role"])
                except ValueError:
                    logger.warning("Token verification failed: invalid role claim")
                    return None
                if claimed_role != role:
                    logger.warning("Token verification failed: claimed role does not match server role binding")
                    return None
        elif "role" in claims:
            try:
                role = self.resolve_role(claims["role"])
            except ValueError as err:
                logger.warning("Token verification failed: %s", err)
                return None
        else:
            # Least-privilege default when no role claim is present
            role = UserRole.VIEWER

        return _create_sealed_user_context(
            uid=uid,
            email=email,
            role=role,
            tenant_id=tenant_id,
            token_claims=claims,
        )


# ==============================================================================
# SECTION 2: FORMAL PERSISTENCE BACKENDS (Stage 4 & Phase 4.1 Hardened)
# ==============================================================================

class PersistenceBackend(abc.ABC):
    """Abstract persistence interface decoupling local simulation from cloud storage."""

    @property
    @abc.abstractmethod
    def backend_type(self) -> str:
        """Returns the declared backend identifier (e.g. 'local_simulation' or 'cloud_firestore')."""
        ...

    @abc.abstractmethod
    def save_artifact(self, doc: FirestoreArtifactDocument) -> None: ...

    @abc.abstractmethod
    def get_artifact(self, sha256: str, tenant_id: str) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def save_findings(self, sha256: str, tenant_id: str, findings: List[Dict[str, Any]]) -> int: ...

    @abc.abstractmethod
    def get_findings(self, sha256: str, tenant_id: str) -> List[Dict[str, Any]]: ...

    @abc.abstractmethod
    def save_job(self, doc: FirestoreJobDocument) -> None: ...

    @abc.abstractmethod
    def update_job(self, job_id: str, tenant_id: str, updates: Dict[str, Any]) -> bool: ...

    @abc.abstractmethod
    def get_job(self, job_id: str, tenant_id: str) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def store_blob(self, path: str, data: bytes, tenant_id: str) -> str: ...

    @abc.abstractmethod
    def get_blob(self, path: str, tenant_id: str) -> Optional[bytes]: ...


class LocalSimulationPersistenceAdapter(PersistenceBackend):
    """
    Local in-memory simulation persistence adapter.
    Explicitly labeled as simulation; does not claim to be Cloud Firestore.
    Strictly enforces tenant isolation and path/identifier validation.
    """

    def __init__(self, storage_bucket: str = "reverse-forge-local-sim"):
        self.storage_bucket = validate_document_id(storage_bucket, "storage_bucket")
        self._lock = threading.Lock()
        self._tenant_artifacts: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._tenant_findings: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        self._tenant_jobs: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._tenant_blobs: Dict[str, Dict[str, bytes]] = {}

    @property
    def backend_type(self) -> str:
        return "local_simulation"

    def save_artifact(self, doc: FirestoreArtifactDocument) -> None:
        t_id = validate_tenant_id(doc.tenant_id)
        sha = validate_artifact_sha256(doc.sha256)
        validate_document_id(doc.filename, "filename")
        with self._lock:
            if t_id not in self._tenant_artifacts:
                self._tenant_artifacts[t_id] = {}
            payload = asdict(doc)
            payload["tenant_id"] = t_id
            payload["sha256"] = sha
            self._tenant_artifacts[t_id][sha] = payload

    def get_artifact(self, sha256: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        t_id = validate_tenant_id(tenant_id)
        sha = validate_artifact_sha256(sha256)
        with self._lock:
            tenant_store = self._tenant_artifacts.get(t_id, {})
            rec = tenant_store.get(sha)
            if rec is None:
                return None
            if rec.get("tenant_id") != t_id:
                raise PersistencePermissionError("Cross-tenant artifact ownership mismatch")
            return dict(rec)

    def save_findings(self, sha256: str, tenant_id: str, findings: List[Dict[str, Any]]) -> int:
        t_id = validate_tenant_id(tenant_id)
        sha = validate_artifact_sha256(sha256)
        sanitized: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings):
            fid = validate_document_id(str(f.get("finding_id") or f"RF-FIND-{idx + 1:03d}"), "finding_id")
            if f.get("tenant_id") and f.get("tenant_id") != t_id:
                raise PersistencePermissionError("Finding tenant_id does not match target tenant_id")
            f_copy = dict(f)
            f_copy["finding_id"] = fid
            f_copy["tenant_id"] = t_id
            sanitized.append(f_copy)
        with self._lock:
            if t_id not in self._tenant_findings:
                self._tenant_findings[t_id] = {}
            self._tenant_findings[t_id][sha] = sanitized
            if t_id in self._tenant_artifacts and sha in self._tenant_artifacts[t_id]:
                self._tenant_artifacts[t_id][sha]["findings_count"] = len(sanitized)
            return len(sanitized)

    def get_findings(self, sha256: str, tenant_id: str) -> List[Dict[str, Any]]:
        t_id = validate_tenant_id(tenant_id)
        sha = validate_artifact_sha256(sha256)
        with self._lock:
            tenant_store = self._tenant_findings.get(t_id, {})
            items = tenant_store.get(sha, [])
            for item in items:
                if item.get("tenant_id") and item.get("tenant_id") != t_id:
                    raise PersistencePermissionError("Cross-tenant finding ownership mismatch")
            return [dict(x) for x in items]

    def save_job(self, doc: FirestoreJobDocument) -> None:
        t_id = validate_tenant_id(doc.tenant_id)
        jid = validate_document_id(doc.job_id, "job_id")
        validate_artifact_sha256(doc.artifact_sha256)
        with self._lock:
            if t_id not in self._tenant_jobs:
                self._tenant_jobs[t_id] = {}
            payload = asdict(doc)
            payload["tenant_id"] = t_id
            payload["job_id"] = jid
            self._tenant_jobs[t_id][jid] = payload

    def update_job(self, job_id: str, tenant_id: str, updates: Dict[str, Any]) -> bool:
        t_id = validate_tenant_id(tenant_id)
        jid = validate_document_id(job_id, "job_id")
        if "tenant_id" in updates and updates["tenant_id"] != t_id:
            raise PersistencePermissionError("Cannot change job tenant_id across tenants")
        with self._lock:
            tenant_jobs = self._tenant_jobs.get(t_id, {})
            if jid in tenant_jobs:
                if tenant_jobs[jid].get("tenant_id") != t_id:
                    raise PersistencePermissionError("Job tenant ownership mismatch")
                tenant_jobs[jid].update(updates)
                tenant_jobs[jid]["tenant_id"] = t_id
                tenant_jobs[jid]["updated_at"] = datetime.now(timezone.utc).isoformat()
                return True
            return False

    def get_job(self, job_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        t_id = validate_tenant_id(tenant_id)
        jid = validate_document_id(job_id, "job_id")
        with self._lock:
            tenant_jobs = self._tenant_jobs.get(t_id, {})
            rec = tenant_jobs.get(jid)
            if rec is None:
                return None
            if rec.get("tenant_id") != t_id:
                raise PersistencePermissionError("Cross-tenant job ownership mismatch")
            return dict(rec)

    def store_blob(self, path: str, data: bytes, tenant_id: str) -> str:
        t_id = validate_tenant_id(tenant_id)
        clean_path = validate_storage_blob_path(path)
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Blob data must be bytes")
        with self._lock:
            if t_id not in self._tenant_blobs:
                self._tenant_blobs[t_id] = {}
            self._tenant_blobs[t_id][clean_path] = bytes(data)
            return f"local-sim://{self.storage_bucket}/{t_id}/{clean_path}"

    def get_blob(self, path: str, tenant_id: str) -> Optional[bytes]:
        t_id = validate_tenant_id(tenant_id)
        clean_path = validate_storage_blob_path(path)
        with self._lock:
            tenant_blobs = self._tenant_blobs.get(t_id, {})
            return tenant_blobs.get(clean_path)


class ProductionFirestoreStorageAdapter(PersistenceBackend):
    """
    Production Google Cloud Firestore and Cloud Storage adapter.
    Enforces strict identifier/path validation, tenant ownership checks on both reads and writes,
    and distinguishes NotFound (returns None) from PermissionDenied and backend outages (raises typed errors).
    """

    def __init__(
        self,
        project_id: str,
        storage_bucket: str,
        firestore_client: Optional[Any] = None,
        storage_client: Optional[Any] = None,
    ):
        self.project_id = validate_document_id(project_id, "project_id")
        self.storage_bucket = validate_document_id(storage_bucket, "storage_bucket")
        self._db = firestore_client
        self._storage = storage_client
        self._bucket = None
        self._init_clients()

    def _init_clients(self) -> None:
        if self._db is not None and self._storage is not None:
            try:
                self._bucket = self._storage.bucket(self.storage_bucket)
            except Exception as exc:
                raise PersistenceUnavailableError(
                    f"Failed to bind storage bucket '{self.storage_bucket}': {type(exc).__name__}"
                ) from exc
            return

        key_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY")
        emulator_host = os.environ.get("FIRESTORE_EMULATOR_HOST")

        if not emulator_host and (not key_path or not os.path.exists(key_path)):
            raise RuntimeError(
                "Production Google Cloud Firestore/Storage unavailable: "
                "FIREBASE_SERVICE_ACCOUNT_KEY is missing or does not exist"
            )

        if firestore is None or storage is None:
            raise RuntimeError(
                "Production Google Cloud Firestore/Storage unavailable: "
                "google-cloud-firestore or google-cloud-storage packages are not installed."
            )

        try:
            if emulator_host:
                self._db = firestore.Client(project=self.project_id)
                self._storage = storage.Client(project=self.project_id)
                self._bucket = self._storage.bucket(self.storage_bucket)
            elif key_path and os.path.exists(key_path):
                creds = service_account.Credentials.from_service_account_file(key_path)
                self._db = firestore.Client(project=self.project_id, credentials=creds)
                self._storage = storage.Client(project=self.project_id, credentials=creds)
                self._bucket = self._storage.bucket(self.storage_bucket)
        except Exception as exc:
            raise PersistenceUnavailableError(
                f"Failed to initialize Google Cloud clients: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def _classify_and_raise_backend_error(operation: str, exc: Exception) -> None:
        """Translate SDK/transport exceptions into typed persistence errors without leaking secrets."""
        if isinstance(exc, (PersistenceError, PersistencePermissionError, ValueError, TypeError)):
            raise exc
        cls_name = exc.__class__.__name__.lower()
        code = getattr(exc, "code", None)
        code_val = code() if callable(code) else code
        if (
            isinstance(exc, PermissionError)
            or "permission" in cls_name
            or "forbidden" in cls_name
            or "unauthorized" in cls_name
            or code_val in (401, 403, "PERMISSION_DENIED", "UNAUTHENTICATED")
        ):
            raise PersistencePermissionError(
                f"Backend permission denied during {operation} ({exc.__class__.__name__})"
            ) from exc
        raise PersistenceUnavailableError(
            f"Backend storage failure during {operation} ({exc.__class__.__name__})"
        ) from exc

    @staticmethod
    def _is_not_found_exception(exc: Exception) -> bool:
        cls_name = exc.__class__.__name__.lower()
        code = getattr(exc, "code", None)
        code_val = code() if callable(code) else code
        return "notfound" in cls_name or "not_found" in cls_name or code_val in (404, "NOT_FOUND")

    @property
    def backend_type(self) -> str:
        return "cloud_firestore"

    def save_artifact(self, doc: FirestoreArtifactDocument) -> None:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(doc.tenant_id)
        sha = validate_artifact_sha256(doc.sha256)
        validate_document_id(doc.filename, "filename")
        data = asdict(doc)
        data["tenant_id"] = t_id
        data["sha256"] = sha
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        try:
            ref = self._db.collection("tenants").document(t_id).collection("artifacts").document(sha)
            ref.set(data)
        except Exception as exc:
            self._classify_and_raise_backend_error("save_artifact", exc)

    def get_artifact(self, sha256: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        sha = validate_artifact_sha256(sha256)
        try:
            ref = self._db.collection("tenants").document(t_id).collection("artifacts").document(sha)
            snap = ref.get()
        except Exception as exc:
            if self._is_not_found_exception(exc):
                return None
            self._classify_and_raise_backend_error("get_artifact", exc)
            return None

        if not snap.exists:
            return None
        record = snap.to_dict()
        if not isinstance(record, dict):
            raise PersistenceUnavailableError("Corrupted artifact record returned by Firestore")
        if record.get("tenant_id") != t_id:
            raise PersistencePermissionError(
                f"Tenant isolation violation on read: record tenant '{record.get('tenant_id')}' != '{t_id}'"
            )
        return record

    def save_findings(self, sha256: str, tenant_id: str, findings: List[Dict[str, Any]]) -> int:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        sha = validate_artifact_sha256(sha256)
        try:
            batch = self._db.batch()
            findings_col = (
                self._db.collection("tenants")
                .document(t_id)
                .collection("artifacts")
                .document(sha)
                .collection("findings")
            )
            saved_count = 0
            for f in findings:
                if f.get("tenant_id") and f.get("tenant_id") != t_id:
                    raise PersistencePermissionError("Finding tenant_id mismatch during save_findings")
                raw_fid = f.get("finding_id") or hashlib.sha256(
                    json.dumps(f, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()[:16]
                fid = validate_document_id(str(raw_fid), "finding_id")
                f_copy = dict(f)
                f_copy["finding_id"] = fid
                f_copy["tenant_id"] = t_id
                f_copy["saved_at"] = datetime.now(timezone.utc).isoformat()
                ref = findings_col.document(fid)
                batch.set(ref, f_copy)
                saved_count += 1

            art_ref = self._db.collection("tenants").document(t_id).collection("artifacts").document(sha)
            batch.set(
                art_ref,
                {
                    "tenant_id": t_id,
                    "sha256": sha,
                    "findings_count": saved_count,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                merge=True,
            )
            batch.commit()
            return saved_count
        except Exception as exc:
            self._classify_and_raise_backend_error("save_findings", exc)
            return 0

    def get_findings(self, sha256: str, tenant_id: str) -> List[Dict[str, Any]]:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        sha = validate_artifact_sha256(sha256)
        try:
            findings_col = (
                self._db.collection("tenants")
                .document(t_id)
                .collection("artifacts")
                .document(sha)
                .collection("findings")
            )
            docs = list(findings_col.stream())
        except Exception as exc:
            if self._is_not_found_exception(exc):
                return []
            self._classify_and_raise_backend_error("get_findings", exc)
            return []

        results: List[Dict[str, Any]] = []
        for d in docs:
            rec = d.to_dict()
            if not isinstance(rec, dict):
                raise PersistenceUnavailableError("Corrupted finding document returned by Firestore")
            if rec.get("tenant_id") and rec.get("tenant_id") != t_id:
                raise PersistencePermissionError(
                    f"Tenant isolation violation in findings stream: '{rec.get('tenant_id')}' != '{t_id}'"
                )
            results.append(rec)
        return results

    def save_job(self, doc: FirestoreJobDocument) -> None:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(doc.tenant_id)
        jid = validate_document_id(doc.job_id, "job_id")
        validate_artifact_sha256(doc.artifact_sha256)
        data = asdict(doc)
        data["tenant_id"] = t_id
        data["job_id"] = jid
        try:
            ref = self._db.collection("tenants").document(t_id).collection("jobs").document(jid)
            ref.set(data)
        except Exception as exc:
            self._classify_and_raise_backend_error("save_job", exc)

    def update_job(self, job_id: str, tenant_id: str, updates: Dict[str, Any]) -> bool:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        jid = validate_document_id(job_id, "job_id")
        if "tenant_id" in updates and updates["tenant_id"] != t_id:
            raise PersistencePermissionError("Cannot modify job tenant_id across tenants")
        try:
            ref = self._db.collection("tenants").document(t_id).collection("jobs").document(jid)
            snap = ref.get()
            if not snap.exists:
                return False
            existing = snap.to_dict() or {}
            if existing.get("tenant_id") and existing.get("tenant_id") != t_id:
                raise PersistencePermissionError("Job tenant ownership mismatch on update_job")
            up = dict(updates)
            up["tenant_id"] = t_id
            up["updated_at"] = datetime.now(timezone.utc).isoformat()
            ref.update(up)
            return True
        except Exception as exc:
            if self._is_not_found_exception(exc):
                return False
            self._classify_and_raise_backend_error("update_job", exc)
            return False

    def get_job(self, job_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        if self._db is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        jid = validate_document_id(job_id, "job_id")
        try:
            ref = self._db.collection("tenants").document(t_id).collection("jobs").document(jid)
            snap = ref.get()
        except Exception as exc:
            if self._is_not_found_exception(exc):
                return None
            self._classify_and_raise_backend_error("get_job", exc)
            return None

        if not snap.exists:
            return None
        record = snap.to_dict()
        if not isinstance(record, dict):
            raise PersistenceUnavailableError("Corrupted job record returned by Firestore")
        if record.get("tenant_id") != t_id:
            raise PersistencePermissionError("Job tenant ownership mismatch on get_job")
        return record

    def store_blob(self, path: str, data: bytes, tenant_id: str) -> str:
        if self._storage is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        clean_path = validate_storage_blob_path(path)
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("store_blob requires bytes payload")
        try:
            if self._bucket is None:
                self._bucket = self._storage.bucket(self.storage_bucket)
            blob_name = f"tenants/{t_id}/{clean_path}"
            blob = self._bucket.blob(blob_name)
            blob.upload_from_string(bytes(data), content_type="application/octet-stream")
            return f"gs://{self.storage_bucket}/{blob_name}"
        except Exception as exc:
            self._classify_and_raise_backend_error("store_blob", exc)
            return ""

    def get_blob(self, path: str, tenant_id: str) -> Optional[bytes]:
        if self._storage is None:
            self._init_clients()
        t_id = validate_tenant_id(tenant_id)
        clean_path = validate_storage_blob_path(path)
        try:
            if self._bucket is None:
                self._bucket = self._storage.bucket(self.storage_bucket)
            blob_name = f"tenants/{t_id}/{clean_path}"
            blob = self._bucket.blob(blob_name)
            return blob.download_as_bytes()
        except Exception as exc:
            if self._is_not_found_exception(exc):
                return None
            self._classify_and_raise_backend_error("get_blob", exc)
            return None


# ==============================================================================
# SECTION 3: UNIFIED FIREBASE SYNC MANAGER (Stage 4 & Phase 4.1 Hardened)
# ==============================================================================

class FirebaseSyncManager:
    """
    Manages synchronization of reverse-engineering findings, jobs, and binaries
    with explicit backend selection and strict principal-derived tenant authorization.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        storage_bucket: Optional[str] = None,
        force_local_sim: bool = False,
    ):
        self.project_id = project_id or os.environ.get("FIREBASE_PROJECT_ID", "reverse-forge-local")
        self.storage_bucket = storage_bucket or os.environ.get("FIREBASE_STORAGE_BUCKET", "reverse-forge-artifacts.appspot.com")
        self.auth = FirebaseAuthManager(self.project_id)

        env_mode = os.environ.get("REVERSE_FORGE_ENV", "").lower()
        is_production = env_mode == "production" and not force_local_sim

        if is_production:
            try:
                self.backend: PersistenceBackend = ProductionFirestoreStorageAdapter(
                    project_id=self.project_id,
                    storage_bucket=self.storage_bucket,
                )
            except RuntimeError as err:
                logger.error("Production persistence initialization failed: %s", err)
                raise
        else:
            self.backend = LocalSimulationPersistenceAdapter(storage_bucket=self.storage_bucket)

    @staticmethod
    def _require_verified_user(user: Optional[AuthUserContext], require_modify: bool = False) -> AuthUserContext:
        if user is None or not isinstance(user, AuthUserContext) or not user.is_cryptographically_verified():
            raise PermissionError("Operation requires a cryptographically verified AuthUserContext")
        validate_tenant_id(user.tenant_id)
        if require_modify and not user.can_modify():
            raise PermissionError(f"User role '{user.role.value}' does not permit modifying persistence state")
        return user

    @classmethod
    def _resolve_tenant(cls, user: Optional[AuthUserContext], tenant_id: Optional[str]) -> str:
        """
        Derive tenant authorization strictly from the authenticated principal.
        Caller-supplied tenant_id without a verified principal is rejected.
        """
        verified_user = cls._require_verified_user(user, require_modify=False)
        if tenant_id is not None:
            validate_tenant_id(tenant_id)
            if tenant_id != verified_user.tenant_id:
                raise PersistencePermissionError(
                    f"Cross-tenant access denied: user tenant '{verified_user.tenant_id}' cannot access '{tenant_id}'"
                )
        return verified_user.tenant_id

    def sync_artifact(
        self,
        sha256: str,
        filename: str,
        size_bytes: int,
        format_name: str,
        architecture: str,
        entropy: float,
        overall_posture: str,
        user: AuthUserContext,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FirestoreArtifactDocument:
        """Upsert artifact record with strict principal-derived tenant enforcement."""
        verified_user = self._require_verified_user(user, require_modify=True)
        clean_sha = validate_artifact_sha256(sha256)
        safe_fname = validate_document_id(os.path.basename(filename), "filename")

        doc = FirestoreArtifactDocument(
            sha256=clean_sha,
            filename=safe_fname,
            size_bytes=int(size_bytes),
            format_name=str(format_name),
            architecture=str(architecture),
            entropy=float(entropy),
            overall_posture=str(overall_posture),
            uploaded_by=verified_user.uid,
            tenant_id=verified_user.tenant_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            storage_path=f"artifacts/{verified_user.tenant_id}/{clean_sha}/{safe_fname}",
            metadata=metadata or {},
        )
        self.backend.save_artifact(doc)
        return doc

    def sync_findings(
        self,
        sha256: str,
        findings_list: List[Dict[str, Any]],
        user: AuthUserContext,
    ) -> int:
        """Batch write findings ensuring verified tenant and role authorization."""
        verified_user = self._require_verified_user(user, require_modify=True)
        clean_sha = validate_artifact_sha256(sha256)

        stored_findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()
        for idx, f in enumerate(findings_list):
            if f.get("tenant_id") and f.get("tenant_id") != verified_user.tenant_id:
                raise PermissionError("Cross-tenant finding payload rejected")
            fid = validate_document_id(str(f.get("finding_id", f"RF-FIND-{idx + 1:03d}")), "finding_id")
            doc = FirestoreFindingDocument(
                finding_id=fid,
                cwe_id=str(f.get("cwe_id", "CWE-UNKNOWN")),
                title=str(f.get("title", "Unnamed Finding")),
                severity=str(f.get("severity", "MEDIUM")),
                cvss_score=float(f.get("cvss_score", 5.0)),
                location_va=str(f.get("location_va", "N/A")),
                sink_or_section=str(f.get("sink_or_section", "")),
                evidence=str(f.get("evidence", "")),
                remediation=str(f.get("remediation", "")),
                detected_at=now,
                tenant_id=verified_user.tenant_id,
            )
            stored_findings.append(asdict(doc))

        return self.backend.save_findings(clean_sha, verified_user.tenant_id, stored_findings)

    def archive_binary(
        self,
        sha256: str,
        filename: str,
        data: bytes,
        user: AuthUserContext,
    ) -> str:
        """Archive binary payload enforcing tenant path prefix and path validation."""
        verified_user = self._require_verified_user(user, require_modify=True)
        clean_sha = validate_artifact_sha256(sha256)
        safe_fname = validate_document_id(os.path.basename(filename), "filename")
        path = f"artifacts/{verified_user.tenant_id}/{clean_sha}/{safe_fname}"
        return self.backend.store_blob(path, data, verified_user.tenant_id)

    def archive_report(
        self,
        sha256: str,
        report_format: str,
        content: str,
        user: AuthUserContext,
    ) -> str:
        """Store generated report ensuring tenant path isolation."""
        verified_user = self._require_verified_user(user, require_modify=True)
        clean_sha = validate_artifact_sha256(sha256)
        ext = "sarif" if report_format == "sarif" else ("json" if report_format == "sbom" else "md")
        path = f"reports/{verified_user.tenant_id}/{clean_sha}/report.{ext}"
        return self.backend.store_blob(path, content.encode("utf-8"), verified_user.tenant_id)

    def create_analysis_job(
        self,
        artifact_sha256: str,
        job_type: str,
        user: AuthUserContext,
    ) -> FirestoreJobDocument:
        """Initialize an asynchronous job record tied to the verified user's tenant."""
        verified_user = self._require_verified_user(user, require_modify=True)
        clean_sha = validate_artifact_sha256(artifact_sha256)
        job_id = f"job_{hashlib.sha256(f'{clean_sha}:{verified_user.uid}:{time.time_ns()}'.encode()).hexdigest()[:16]}"
        now = datetime.now(timezone.utc).isoformat()
        job = FirestoreJobDocument(
            job_id=job_id,
            artifact_sha256=clean_sha,
            job_type=str(job_type),
            status="QUEUED",
            progress_pct=0,
            current_stage="INITIALIZING",
            submitted_by=verified_user.uid,
            tenant_id=verified_user.tenant_id,
            created_at=now,
            updated_at=now,
        )
        self.backend.save_job(job)
        return job

    def update_job_progress(
        self,
        job_id: str,
        status: str,
        progress_pct: int,
        stage: str,
        user: Optional[AuthUserContext] = None,
        tenant_id: Optional[str] = None,
        error: Optional[str] = None,
        result_summary: Optional[Dict[str, Any]] = None,
    ) -> bool:
        verified_user = self._require_verified_user(user, require_modify=True)
        t_id = self._resolve_tenant(verified_user, tenant_id)
        jid = validate_document_id(job_id, "job_id")
        updates: Dict[str, Any] = {
            "status": str(status),
            "progress_pct": int(progress_pct),
            "current_stage": str(stage),
        }
        if error:
            updates["error"] = str(error)
        if result_summary:
            updates["result_summary"] = dict(result_summary)
        return self.backend.update_job(jid, t_id, updates)

    def get_job(self, job_id: str, user: Optional[AuthUserContext] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        t_id = self._resolve_tenant(user, tenant_id)
        jid = validate_document_id(job_id, "job_id")
        return self.backend.get_job(jid, t_id)

    def get_artifact(self, sha256: str, user: Optional[AuthUserContext] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        t_id = self._resolve_tenant(user, tenant_id)
        clean_sha = validate_artifact_sha256(sha256)
        return self.backend.get_artifact(clean_sha, t_id)

    def get_findings(self, sha256: str, user: Optional[AuthUserContext] = None, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        t_id = self._resolve_tenant(user, tenant_id)
        clean_sha = validate_artifact_sha256(sha256)
        return self.backend.get_findings(clean_sha, t_id)

    def get_sync_status(self) -> Dict[str, Any]:
        """Provides an honest status report distinguishing simulation from cloud persistence."""
        is_sim = self.backend.backend_type == "local_simulation"
        art_count = 0
        find_count = 0
        job_count = 0
        obj_count = 0

        if isinstance(self.backend, LocalSimulationPersistenceAdapter):
            for t_arts in self.backend._tenant_artifacts.values():
                art_count += len(t_arts)
            for t_finds in self.backend._tenant_findings.values():
                find_count += len(t_finds)
            for t_jobs in self.backend._tenant_jobs.values():
                job_count += len(t_jobs)
            for t_blobs in self.backend._tenant_blobs.values():
                obj_count += len(t_blobs)

        return {
            "project_id": self.project_id,
            "storage_bucket": self.storage_bucket,
            "backend_type": self.backend.backend_type,
            "firestore": {
                "artifacts_count": art_count,
                "findings_collections": find_count,
                "jobs_count": job_count,
                "backend": self.backend.backend_type,
            },
            "storage": {
                "objects_count": obj_count,
                "backend": self.backend.backend_type,
            },
            "authenticated_user": None,
            "mode": "in_memory_simulation" if is_sim else "live_cloud",
        }

    def sync_analysis_dossier(
        self,
        filepath: str,
        dossier: Dict[str, Any],
        raw_bytes: bytes,
        auth_user: AuthUserContext,
    ) -> Dict[str, Any]:
        verified_user = self._require_verified_user(auth_user, require_modify=True)
        filename = validate_document_id(os.path.basename(filepath), "filename")
        sha256 = validate_artifact_sha256(dossier.get("sha256") or hashlib.sha256(raw_bytes).hexdigest())
        size_bytes = len(raw_bytes)
        fmt = str(dossier.get("format", "UNKNOWN"))
        arch = str(dossier.get("architecture", "UNKNOWN"))
        entropy = float(dossier.get("entropy", 0.0))
        posture = str(dossier.get("hardening_posture", "STANDARD"))

        self.sync_artifact(
            sha256=sha256,
            filename=filename,
            size_bytes=size_bytes,
            format_name=fmt,
            architecture=arch,
            entropy=entropy,
            overall_posture=posture,
            user=verified_user,
            metadata={"engine": "R3V3R53//F0RG3 v32.0"},
        )

        findings = dossier.get("vulnerabilities", [])
        findings_cnt = self.sync_findings(sha256, findings, verified_user)

        bin_uri = self.archive_binary(sha256, filename, raw_bytes, verified_user)
        sarif_uri = self.archive_report(sha256, "sarif", json.dumps(dossier.get("sarif_report", {})), verified_user)

        return {
            "status": "ok",
            "project_id": self.project_id,
            "sha256": sha256,
            "firestore_path": f"tenants/{verified_user.tenant_id}/artifacts/{sha256}",
            "findings_count": findings_cnt,
            "storage_binary_uri": bin_uri,
            "storage_sarif_uri": sarif_uri,
            "backend": self.backend.backend_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global default instance
firebase_sync = FirebaseSyncManager(force_local_sim=True)
