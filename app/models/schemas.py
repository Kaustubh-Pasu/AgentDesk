"""Strict Pydantic v2 schemas.

Everything that crosses a trust boundary (browser → app, LLM → app, ANS → app, remote agent → app)
is parsed through one of these models. All models forbid unknown fields, bound every string and
array, and use enums for anything that selects behaviour. The LLM can never "invent" a capability:
capabilities are an enum mapped to prewritten handlers, and forbidden names are rejected explicitly.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
import unicodedata
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------- text helpers
# Invisible / bidi-override code points are built from integers so that no invisible character ever
# appears literally in this source file (zero-width 200B-200F, separators + bidi 2028-202E, isolates
# 2066-2069, BOM FEFF).
_INVISIBLE = "".join(
    chr(c) for c in (*range(0x200B, 0x2010), *range(0x2028, 0x202F), *range(0x2066, 0x206A), 0xFEFF)
)
_CONTROL = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\x9f" + re.escape(_INVISIBLE) + "]")
_WS = re.compile(r"[ \t\r\f\v]+")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
_SEMVER = re.compile(r"^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\Z")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z")


def clean_text(value: str) -> str:
    """NFC-normalise, drop control/bidi/zero-width characters, collapse horizontal whitespace."""
    value = unicodedata.normalize("NFC", value)
    value = _CONTROL.sub("", value)
    value = _WS.sub(" ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def _bounded(max_len: int, min_len: int = 0) -> Any:
    return Annotated[
        StrictStr,
        AfterValidator(clean_text),
        StringConstraints(min_length=min_len, max_length=max_len),
    ]


def _validate_https_url(value: str) -> str:
    value = value.strip()
    if len(value) > 2048 or "\\" in value or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("invalid URL")
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ValueError("only https:// URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL must not contain credentials")
    host = (parts.hostname or "").lower()
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels):
        raise ValueError("URL host must be a DNS name")
    if labels[-1].isdigit():
        raise ValueError("URL host must not be an IP address")
    return value


HttpsUrl = Annotated[StrictStr, AfterValidator(_validate_https_url)]
ShortText = _bounded(120, 1)
OptionalShortText = _bounded(120)
PriceText = _bounded(40)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)


# --------------------------------------------------------------------------- capabilities
class Capability(enum.StrEnum):
    BUSINESS_INFORMATION = "business_information"
    HOURS = "hours"
    LOCATION = "location"
    MENU_CATALOG = "menu_catalog"
    SERVICES_CATALOG = "services_catalog"
    FAQ = "faq"


#: Names that must never become agent capabilities. They are not in the enum (so they fail validation
#: anyway); listing them lets us raise a precise, auditable policy error.
FORBIDDEN_CAPABILITIES = frozenset(
    {
        "shell",
        "filesystem",
        "arbitrary_http",
        "http_request",
        "network_fetch",
        "dns_write",
        "ans_write",
        "payment",
        "purchase",
        "send_email",
        "account_admin",
        "secrets",
        "generic_tool_execution",
        "execute",
        "eval",
        "sql",
    }
)


class BusinessCategory(enum.StrEnum):
    RESTAURANT = "restaurant"
    RETAIL = "retail"
    PROFESSIONAL_SERVICES = "professional_services"
    HEALTH_WELLNESS = "health_wellness"
    HOSPITALITY = "hospitality"
    EDUCATION = "education"
    TECHNOLOGY = "technology"
    OTHER = "other"


# --------------------------------------------------------------------------- BusinessProfile
class PublicContact(StrictModel):
    phone: _bounded(40) = ""  # type: ignore[valid-type]
    email: _bounded(254) = ""  # type: ignore[valid-type]
    website: HttpsUrl | None = None

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if v and not _EMAIL.match(v):
            raise ValueError("invalid email")
        return v

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str) -> str:
        if v and not re.fullmatch(r"[0-9+()\-. x/]{5,40}", v):
            raise ValueError("invalid phone")
        return v


class HoursEntry(StrictModel):
    days: _bounded(60, 1)  # type: ignore[valid-type]
    hours: _bounded(80, 1)  # type: ignore[valid-type]


class ServiceItem(StrictModel):
    name: ShortText  # type: ignore[valid-type]
    description: _bounded(400) = ""  # type: ignore[valid-type]
    price: PriceText = ""  # type: ignore[valid-type]


class MenuItem(StrictModel):
    name: ShortText  # type: ignore[valid-type]
    description: _bounded(400) = ""  # type: ignore[valid-type]
    price: PriceText = ""  # type: ignore[valid-type]
    section: _bounded(80) = ""  # type: ignore[valid-type]


class FaqItem(StrictModel):
    question: _bounded(300, 1)  # type: ignore[valid-type]
    answer: _bounded(800, 1)  # type: ignore[valid-type]


class BusinessProfile(StrictModel):
    """The ONLY thing website ingestion can produce: bounded, inert data."""

    business_name: ShortText  # type: ignore[valid-type]
    description: _bounded(1200) = ""  # type: ignore[valid-type]
    category: BusinessCategory = BusinessCategory.OTHER
    address: _bounded(300) = ""  # type: ignore[valid-type]
    contact: PublicContact = Field(default_factory=PublicContact)
    hours: list[HoursEntry] = Field(default_factory=list, max_length=14)
    services: list[ServiceItem] = Field(default_factory=list, max_length=50)
    menu_items: list[MenuItem] = Field(default_factory=list, max_length=100)
    faq: list[FaqItem] = Field(default_factory=list, max_length=30)
    source_urls: list[HttpsUrl] = Field(default_factory=list, max_length=10)

    def content_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json")).encode()).hexdigest()

    def derived_capabilities(self) -> list[Capability]:
        """Capabilities that the content can actually support (deterministic; not model-chosen)."""
        caps = [Capability.BUSINESS_INFORMATION]
        if self.hours:
            caps.append(Capability.HOURS)
        if self.address:
            caps.append(Capability.LOCATION)
        if self.menu_items:
            caps.append(Capability.MENU_CATALOG)
        if self.services:
            caps.append(Capability.SERVICES_CATALOG)
        if self.faq:
            caps.append(Capability.FAQ)
        return caps


class ExtractionOutput(StrictModel):
    """Exact shape the quarantined extraction model must emit."""

    profile: BusinessProfile
    capabilities: list[Capability] = Field(default_factory=list, max_length=len(Capability))


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- browser/API inputs
class LoginInput(StrictModel):
    email: _bounded(254, 3)  # type: ignore[valid-type]
    password: Annotated[StrictStr, StringConstraints(min_length=1, max_length=256)]


class TenantCreateInput(StrictModel):
    """Only writable fields. owner_id / state / role / ans_name can never be mass-assigned."""

    display_name: ShortText  # type: ignore[valid-type]
    source_url: HttpsUrl
    agent_label: Annotated[StrictStr, StringConstraints(min_length=1, max_length=63)]

    @field_validator("agent_label")
    @classmethod
    def _label(cls, v: str) -> str:
        v = v.strip().lower()
        if not _HOST_LABEL.match(v):
            raise ValueError("agent subdomain must be a single DNS label (a-z, 0-9, hyphen)")
        return v


class ProfileConfirmInput(StrictModel):
    profile: BusinessProfile
    capabilities: list[Capability] = Field(max_length=len(Capability))
    row_version: StrictInt = Field(ge=1)
    confirm: StrictBool

    @model_validator(mode="after")
    def _must_confirm(self) -> ProfileConfirmInput:
        if not self.confirm:
            raise ValueError("owner confirmation is required")
        return self


class RevocationReason(enum.StrEnum):
    KEY_COMPROMISE = "KEY_COMPROMISE"
    CESSATION_OF_OPERATION = "CESSATION_OF_OPERATION"
    AFFILIATION_CHANGED = "AFFILIATION_CHANGED"
    SUPERSEDED = "SUPERSEDED"
    UNSPECIFIED = "UNSPECIFIED"


class RevokeInput(StrictModel):
    reason: RevocationReason
    password: Annotated[StrictStr, StringConstraints(min_length=1, max_length=256)]


class FindInput(StrictModel):
    query: _bounded(300, 2)  # type: ignore[valid-type]
    exact_host: _bounded(253) = ""  # type: ignore[valid-type]
    question: _bounded(500) = ""  # type: ignore[valid-type]
    connect: StrictBool = True


# --------------------------------------------------------------------------- semver / ANS names
def parse_semver(value: str) -> tuple[int, int, int]:
    m = _SEMVER.fullmatch(value) if isinstance(value, str) else None  # fullmatch: "1.0.0\n" must not pass
    if not m:
        raise ValueError("version must be MAJOR.MINOR.PATCH")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def bump_patch(value: str) -> str:
    major, minor, patch = parse_semver(value)
    return f"{major}.{minor}.{patch + 1}"


def ans_name_for(host: str, version: str) -> str:
    parse_semver(version)
    return f"ans://v{version}.{host}"


# --------------------------------------------------------------------------- verification / proof
Status = Literal["PASS", "FAIL", "INCOMPLETE"]


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    status: Status
    detail: str = ""
    mandatory: bool = True
    evidence: dict[str, Any] = Field(default_factory=dict)


class AnsEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str | None = None
    ans_name: str | None = None
    status: str | None = None
    environment: str | None = None
    declared_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    checked_at: datetime | None = None
    source: str = ""


class EndpointCheck(BaseModel):
    model_config = ConfigDict(extra="allow")

    protocol: str
    url: str
    status: Status
    detail: str = ""


class CertificateSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str = ""
    subject: str = ""
    san: list[str] = Field(default_factory=list)
    serial: str = ""
    sha256: str = ""
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    chain_status: Status = "INCOMPLETE"
    chain_reason: str = ""
    binding_status: Status = "INCOMPLETE"
    binding_reason: str = ""


class TlsEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status = "INCOMPLETE"
    detail: str = ""
    version: str = ""
    cipher: str = ""
    hostname_verified: bool = False
    leaf_sha256: str = ""
    issuer: str = ""
    subject: str = ""
    san: list[str] = Field(default_factory=list)
    not_after: datetime | None = None


class A2AEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status = "INCOMPLETE"
    detail: str = ""
    card_url: str = ""
    card_valid: bool = False
    card_sha256: str = ""
    name: str = ""
    version: str = ""
    protocol_versions: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    rpc_url: str = ""
    signed: bool = False
    drift: bool = False


class McpEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status = "INCOMPLETE"
    detail: str = ""
    url: str = ""
    handshake: bool = False
    protocol_version: str = ""
    server_name: str = ""
    tools: list[str] = Field(default_factory=list)
    probe_tool: str = ""
    probe_ok: bool = False


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_host: str
    generated_at: datetime
    ans: AnsEvidence = Field(default_factory=AnsEvidence)
    endpoint_checks: list[EndpointCheck] = Field(default_factory=list)
    identity_certificate: CertificateSummary | None = None
    tls: TlsEvidence = Field(default_factory=TlsEvidence)
    a2a: A2AEvidence = Field(default_factory=A2AEvidence)
    mcp: McpEvidence = Field(default_factory=McpEvidence)
    checks: list[CheckResult] = Field(default_factory=list)
    verified: bool = False
    decision: Status = "INCOMPLETE"
    reasons: list[str] = Field(default_factory=list)
