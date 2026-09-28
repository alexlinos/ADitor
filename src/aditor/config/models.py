"""Configuration models for ADitor."""

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Type, TypeVar

T = TypeVar("T")


def build(cls: Type[T], data: Any) -> T:
    """``cls(**data)``, ignoring keys ``cls`` does not declare.

    Older config files carry blocks and keys ADitor no longer reads (the MCP
    era's ``organizational_units``, ``logging``, ``use_ssl``...), and the app
    writes a ``_comment``; none of that should stop a config from loading.
    """
    if not isinstance(data, dict):
        raise ValueError(f"{cls.__name__} must be a JSON object")
    names = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    return cls(**{k: v for k, v in data.items() if k in names})


@dataclass
class ActiveDirectoryConfig:
    """Active Directory connection configuration."""

    server: str
    domain: str
    base_dn: str
    bind_dn: str
    # Kept out of repr(), so logging or printing a config never shows it.
    password: str = field(repr=False)
    server_pool: Optional[List[str]] = None
    timeout: int = 30
    auto_bind: bool = True
    receive_timeout: int = 10

    def __post_init__(self) -> None:
        if not self.server.startswith(("ldap://", "ldaps://")):
            raise ValueError("Server must start with ldap:// or ldaps://")

    @property
    def cleartext_servers(self) -> List[str]:
        """The configured servers reached over plain ``ldap://``.

        ADitor binds with a simple bind and never issues STARTTLS, so the bind
        password crosses the network in clear text to every one of these.
        """
        return [url for url in [self.server] + list(self.server_pool or [])
                if str(url).lower().startswith("ldap://")]


@dataclass
class SecurityConfig:
    """Security configuration for LDAP connections."""

    enable_tls: bool = True
    validate_certificate: bool = True
    ca_cert_file: Optional[str] = None


@dataclass
class PerformanceConfig:
    """Retry and paging configuration."""

    max_retries: int = 3
    retry_delay: float = 1.0
    page_size: int = 1000

    def __post_init__(self) -> None:
        if self.max_retries <= 0 or self.retry_delay <= 0 or self.page_size <= 0:
            raise ValueError(
                "max_retries, retry_delay and page_size must be positive")


@dataclass
class Config:
    """Main configuration class."""

    active_directory: ActiveDirectoryConfig
    security: SecurityConfig
    performance: PerformanceConfig

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        if not isinstance(data, dict) or "active_directory" not in data:
            raise ValueError("config must have an 'active_directory' block")
        return cls(
            active_directory=build(ActiveDirectoryConfig, data["active_directory"]),
            security=build(SecurityConfig, data.get("security") or {}),
            performance=build(PerformanceConfig, data.get("performance") or {}),
        )
