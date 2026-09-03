from __future__ import annotations

import ipaddress
import re
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LEGACY_IPV4_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$")


class NetworkDestinationClass(StrEnum):
    """Source-visible destination class for one canonical network host."""

    LOOPBACK = "loopback"
    EXTERNAL = "external"
    DISALLOWED_LITERAL = "disallowed_literal"


class NetworkAuthorityCode(StrEnum):
    """Stable fail-closed reason codes for network authority decisions."""

    HOST_MISSING = "host_missing"
    HOST_INVALID = "host_invalid"
    HOST_NOT_ALLOWLISTED = "host_not_allowlisted"
    DISALLOWED_LITERAL = "disallowed_literal"
    EXTERNAL_DISABLED = "external_disabled"
    EXTERNAL_EGRESS_UNVERIFIED = "external_egress_unverified"


class AuthorizedNetworkHosts(frozenset[str]):
    """Immutable allowlisted hosts carrying trusted post-resolution egress authority."""

    external_egress_enforced: bool

    def __new__(
        cls,
        values: AbstractSet[str],
        *,
        external_egress_enforced: bool,
    ) -> AuthorizedNetworkHosts:
        if not isinstance(external_egress_enforced, bool):
            raise ValueError("external_egress_enforced must be a boolean")
        instance = super().__new__(cls, values)
        instance.external_egress_enforced = external_egress_enforced
        return instance


class NetworkAuthorityError(PermissionError):
    """Deterministic denial carrying a stable authority reason code."""

    def __init__(self, code: NetworkAuthorityCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class NetworkDestination:
    host: str
    destination_class: NetworkDestinationClass

    @property
    def external(self) -> bool:
        return self.destination_class is NetworkDestinationClass.EXTERNAL


def canonicalize_network_host(value: str) -> str:
    """Validate and canonicalize one trusted host-only allowlist entry.

    The configuration surface accepts hostnames/IP literals, not URLs, ports,
    wildcard patterns, paths, user-info, query strings, fragments, or scoped
    interface identifiers. Numeric-only non-canonical host spellings are rejected
    because system resolvers may interpret legacy forms such as ``127.1`` or a
    single integer as IPv4 even though :mod:`ipaddress` does not treat them as a
    canonical literal.
    """

    raw = str(value).strip()
    if not raw:
        raise ValueError("network allowlist entries must not be empty")
    if raw == "*" or raw.startswith("*."):
        raise ValueError("wildcard network allowlist entries are not supported")
    if "://" in raw or any(token in raw for token in ("/", "?", "#", "@", "%")):
        raise ValueError("network allowlist entries must be unscoped hostnames or IP literals")

    bracketed = raw.startswith("[") or raw.endswith("]")
    if bracketed and not (raw.startswith("[") and raw.endswith("]")):
        raise ValueError("network allowlist entry has mismatched IP-literal brackets")
    candidate = raw[1:-1] if bracketed else raw
    candidate = candidate.rstrip(".").casefold()
    if not candidate:
        raise ValueError("network allowlist entry is invalid")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        if bracketed and address.version != 6:
            raise ValueError("brackets are supported only for IPv6 allowlist literals")
        return address.compressed.casefold()
    if bracketed:
        raise ValueError("bracketed network allowlist entry must be a valid IPv6 literal")

    if ":" in candidate:
        raise ValueError("network allowlist entries must not include ports")
    if _LEGACY_IPV4_RE.fullmatch(candidate):
        raise ValueError(
            "non-canonical numeric network hosts are not accepted as DNS hostnames"
        )
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("network allowlist hostname is not valid IDNA") from exc
    if len(ascii_host) > 253:
        raise ValueError("network allowlist hostname exceeds 253 characters")
    labels = ascii_host.split(".")
    if any(not label or not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("network allowlist hostname contains an invalid DNS label")
    return ascii_host


def classify_network_host(value: str) -> NetworkDestination:
    """Classify a canonical host without performing DNS or routing observation."""

    host = canonicalize_network_host(value)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is None:
        if host == "localhost":
            return NetworkDestination(host, NetworkDestinationClass.LOOPBACK)
        return NetworkDestination(host, NetworkDestinationClass.EXTERNAL)
    if address.is_loopback:
        return NetworkDestination(host, NetworkDestinationClass.LOOPBACK)
    if (
        address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return NetworkDestination(host, NetworkDestinationClass.DISALLOWED_LITERAL)
    return NetworkDestination(host, NetworkDestinationClass.EXTERNAL)


def network_url_destination(url: str) -> NetworkDestination:
    """Parse and classify the URL host without trusting or querying DNS."""

    try:
        host = urlparse(url).hostname or ""
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.HOST_INVALID,
            "network URL host is malformed",
        ) from exc
    if not host:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.HOST_MISSING,
            "network host is not explicitly allowlisted: <missing>",
        )
    try:
        return classify_network_host(host)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.HOST_INVALID,
            f"network host is not a canonical hostname or IP literal: {host}",
        ) from exc


def authorize_network_url(
    url: str,
    *,
    allowed_hosts: AbstractSet[str],
    allow_external_network: bool,
    external_egress_enforced: bool,
) -> NetworkDestination:
    """Authorize source-visible network intent while requiring real egress authority.

    This function intentionally performs no DNS preflight. External DNS names and
    global IP literals are executable only when trusted deployment infrastructure
    asserts that post-resolution egress is constrained at the actual connection
    boundary. That assertion is a prerequisite, not proof supplied by this code.
    """

    destination = network_url_destination(url)
    if destination.host not in allowed_hosts:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.HOST_NOT_ALLOWLISTED,
            f"network host is not explicitly allowlisted: {destination.host}",
        )
    if destination.destination_class is NetworkDestinationClass.DISALLOWED_LITERAL:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.DISALLOWED_LITERAL,
            "network IP literal is not an authorized global or loopback destination: "
            f"{destination.host}",
        )
    if not destination.external:
        return destination
    if not allow_external_network:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.EXTERNAL_DISABLED,
            "external network access is disabled",
        )
    if not external_egress_enforced:
        raise NetworkAuthorityError(
            NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED,
            "external API/browser execution requires trusted deployment enforcement of "
            "post-resolution outbound destinations",
        )
    return destination
