"""Query normalisation for FIND: free text → a small, bounded, enum-tagged capability request.

Deterministic on purpose. Nothing derived from the query can name a URL, host, tool or protocol: the only outputs
are enum tags and a bounded keyword string that is sent to the ANS search API as a search term.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from app.models.schemas import clean_text

MAX_KEYWORDS = 12
_WORD = re.compile(r"[a-z0-9][a-z0-9'\-]{1,30}")
_STOP = frozenset(
    "a an and any are agent agents ai bot can could do does find for from get give have help i in is it know knows looking "
    "me my need of on or please search some someone something tell that the there to want what where which who with you".split())


class IntentTag(enum.StrEnum):
    HOURS = "hours"
    LOCATION = "location"
    MENU = "menu"
    SERVICES = "services"
    BUSINESS_INFO = "business_info"
    VERIFICATION = "verification"
    GENERAL = "general"


_TAG_WORDS: dict[IntentTag, frozenset[str]] = {
    IntentTag.HOURS: frozenset({"hours", "open", "opening", "closing", "schedule"}),
    IntentTag.LOCATION: frozenset({"address", "location", "directions", "near", "nearby"}),
    IntentTag.MENU: frozenset({"menu", "food", "coffee", "cafe", "restaurant", "pizza", "bakery", "drinks", "lunch", "dinner"}),
    IntentTag.SERVICES: frozenset({"services", "service", "pricing", "prices", "catering", "repair", "booking", "consulting"}),
    IntentTag.BUSINESS_INFO: frozenset({"business", "company", "shop", "store", "contact", "phone", "faq"}),
    IntentTag.VERIFICATION: frozenset({"verify", "verification", "trust", "identity", "certificate", "dns", "audit"}),
}


@dataclass(frozen=True)
class CapabilityRequest:
    tags: tuple[IntentTag, ...]
    keywords: tuple[str, ...]

    @property
    def search_text(self) -> str:
        return " ".join(self.keywords)[:256]


def normalize_query(query: str) -> CapabilityRequest:
    words = _WORD.findall(clean_text(query).lower()[:300])
    keywords: list[str] = []
    for word in words:
        if word not in _STOP and word not in keywords:
            keywords.append(word)
    tags = tuple(tag for tag, vocab in _TAG_WORDS.items() if vocab & set(words)) or (IntentTag.GENERAL,)
    return CapabilityRequest(tags=tags, keywords=tuple(keywords[:MAX_KEYWORDS]))
