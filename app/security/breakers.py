"""Circuit breakers (kill switches) driven by environment flags.

When a breaker is open the affected feature returns a clear, safe error while proof / health / existing
read-only agents keep working.
"""

from __future__ import annotations

from enum import StrEnum

from app.settings import Settings


class Feature(StrEnum):
    AGENT_CREATION = "agent_creation"
    EXTERNAL_FETCH = "external_fetch"
    REMOTE_AGENT_CALLS = "remote_agent_calls"
    LLM = "llm"
    WRITES = "writes"


class FeatureDisabled(Exception):
    def __init__(self, feature: Feature) -> None:
        super().__init__(f"{feature.value} is disabled by a circuit breaker")
        self.feature = feature
        self.code = f"feature_disabled_{feature.value}"


def is_enabled(settings: Settings, feature: Feature) -> bool:
    if feature is Feature.AGENT_CREATION:
        return not (settings.disable_agent_creation or settings.read_only_mode)
    if feature is Feature.EXTERNAL_FETCH:
        return not settings.disable_external_fetch
    if feature is Feature.REMOTE_AGENT_CALLS:
        return not settings.disable_remote_agent_calls
    if feature is Feature.LLM:
        return not settings.disable_llm and settings.llm_provider != "none"
    if feature is Feature.WRITES:
        return not settings.read_only_mode
    return False


def require(settings: Settings, feature: Feature) -> None:
    if not is_enabled(settings, feature):
        raise FeatureDisabled(feature)


def snapshot(settings: Settings) -> dict[str, bool]:
    return {feature.value: is_enabled(settings, feature) for feature in Feature}
