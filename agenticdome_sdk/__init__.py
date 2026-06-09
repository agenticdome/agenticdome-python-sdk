from .client import AgentGuardClient

try:
    from .client import GuardrailClient
except Exception:
    GuardrailClient = AgentGuardClient

try:
    from .exceptions import AgentGuardError, AgentGuardHTTPError
except Exception:
    try:
        from .client import AgentGuardError, AgentGuardHTTPError
    except Exception:
        class AgentGuardError(Exception):
            pass

        class AgentGuardHTTPError(AgentGuardError):
            pass


__all__ = [
    "AgentGuardClient",
    "GuardrailClient",
    "AgentGuardError",
    "AgentGuardHTTPError",
]
