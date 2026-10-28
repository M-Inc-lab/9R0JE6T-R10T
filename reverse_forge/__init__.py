__version__ = "26.0.0-rust-bicentennial"
__version_info__ = (26, 0, 0)
__authoritative_version__ = "26.0.0"

from reverse_forge.firebase_sync import ensure_jwt_module as _ensure_jwt_module

_ensure_jwt_module()

from reverse_forge.scripting_api import ForgeScriptingWorkspace, open_binary as open, from_bytes

__all__ = ["__version__", "ForgeScriptingWorkspace", "open", "from_bytes"]
