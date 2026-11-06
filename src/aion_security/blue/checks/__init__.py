from .idp_mfa import IdpMfaCheck

REGISTRY = {IdpMfaCheck.name: IdpMfaCheck}

__all__ = ["IdpMfaCheck", "REGISTRY"]
