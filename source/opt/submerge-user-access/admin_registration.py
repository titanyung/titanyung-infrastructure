"""Minimal entry hook; caller supplies authoritative identity/core bindings."""
from admin_plugin import register_backend


def install(app,admin_request,same_origin_request,verify_view_key,totp_enabled,*,
            backend,allowed_origins,**options):
    return register_backend(app,admin_request,same_origin_request,verify_view_key,
        backend=backend,allowed_origins=allowed_origins,
        auth_mode=lambda:'totp' if totp_enabled() else 'view-key',**options)
