"""Deterministic, extractive answers over a ``BusinessProfile``.

This is the fallback (and the only mode with ``LLM_PROVIDER=none``): no model, no network, no tools.
The profile is inert validated data, so nothing in it can change behaviour; it can only be quoted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.models.schemas import BusinessProfile, Capability

MAX_ANSWER_CHARS = 1800
MAX_QUESTION_CHARS = 500

_WORD = re.compile(r"[a-z0-9']+")
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "at",
        "be",
        "by",
        "can",
        "do",
        "does",
        "for",
        "from",
        "have",
        "how",
        "i",
        "in",
        "is",
        "it",
        "me",
        "my",
        "of",
        "on",
        "or",
        "our",
        "the",
        "to",
        "us",
        "was",
        "what",
        "when",
        "where",
        "which",
        "who",
        "will",
        "with",
        "you",
        "your",
        "please",
        "tell",
        "about",
        "any",
        "there",
        "this",
        "that",
    ]
)

_INTENT_KEYWORDS: dict[Capability, tuple[str, ...]] = {
    Capability.HOURS: (
        "hour",
        "hours",
        "open",
        "opens",
        "opening",
        "close",
        "closes",
        "closing",
        "closed",
        "today",
        "tonight",
        "weekend",
        "weekday",
        "schedule",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ),
    Capability.LOCATION: (
        "where",
        "address",
        "location",
        "located",
        "directions",
        "find",
        "map",
        "street",
        "parking",
    ),
    Capability.MENU_CATALOG: (
        "menu",
        "food",
        "dish",
        "dishes",
        "eat",
        "drink",
        "drinks",
        "coffee",
        "lunch",
        "dinner",
        "breakfast",
        "vegan",
        "vegetarian",
        "dessert",
    ),
    Capability.SERVICES_CATALOG: (
        "service",
        "services",
        "offer",
        "offers",
        "offering",
        "provide",
        "provides",
        "pricing",
        "price",
        "prices",
        "cost",
        "rates",
        "package",
        "packages",
    ),
}

#: Anything that smells like a transaction is outside the MVP and fails closed (spec §36).
_TRANSACTION_WORDS = frozenset(
    [
        "pay",
        "payment",
        "purchase",
        "buy",
        "order",
        "checkout",
        "book",
        "booking",
        "reserve",
        "reservation",
        "refund",
        "charge",
        "invoice",
        "transfer",
        "wire",
        "mandate",
        "settle",
        "settlement",
        "x402",
        "ap2",
        "quote",
    ]
)

UNSUPPORTED_TRANSACTION_TEXT = (
    "This agent is read-only. It cannot take payments, place orders, make bookings or perform any other "
    "transaction, and no such action was performed. Please contact the business directly."
)


@dataclass(frozen=True)
class Answer:
    text: str
    capability: Capability | None
    unsupported: bool = False


def _tokens(text: str) -> list[str]:
    return [t for t in _WORD.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_ANSWER_CHARS else text[: MAX_ANSWER_CHARS - 1].rstrip() + "…"


def is_transaction_request(question: str) -> bool:
    return any(t in _TRANSACTION_WORDS for t in _WORD.findall(question.lower()))


# --------------------------------------------------------------------------- section renderers
def summary_text(profile: BusinessProfile) -> str:
    lines = [profile.business_name]
    if profile.description:
        lines.append(profile.description)
    if profile.address:
        lines.append(f"Address: {profile.address}")
    contact = contact_text(profile)
    if contact:
        lines.append(contact)
    return _clip("\n".join(lines))


def contact_text(profile: BusinessProfile) -> str:
    parts = []
    if profile.contact.phone:
        parts.append(f"Phone: {profile.contact.phone}")
    if profile.contact.email:
        parts.append(f"Email: {profile.contact.email}")
    if profile.contact.website:
        parts.append(f"Website: {profile.contact.website}")
    return " · ".join(parts)


def hours_text(profile: BusinessProfile) -> str:
    if not profile.hours:
        return f"{profile.business_name} has not published opening hours."
    rows = "\n".join(f"- {h.days}: {h.hours}" for h in profile.hours)
    return _clip(f"Opening hours for {profile.business_name}:\n{rows}")


def location_text(profile: BusinessProfile) -> str:
    if not profile.address:
        return f"{profile.business_name} has not published an address."
    contact = contact_text(profile)
    return _clip(
        f"{profile.business_name} is located at {profile.address}." + (f"\n{contact}" if contact else "")
    )


def _item_line(name: str, description: str, price: str) -> str:
    line = f"- {name}"
    if price:
        line += f" ({price})"
    if description:
        line += f": {description}"
    return line


def menu_text(profile: BusinessProfile) -> str:
    if not profile.menu_items:
        return ""
    lines: list[str] = []
    section = None
    for item in profile.menu_items:
        if item.section and item.section != section:
            section = item.section
            lines.append(f"{section}:")
        lines.append(_item_line(item.name, item.description, item.price))
    return _clip(f"Menu for {profile.business_name}:\n" + "\n".join(lines))


def services_text(profile: BusinessProfile) -> str:
    if not profile.services:
        return ""
    lines = [_item_line(s.name, s.description, s.price) for s in profile.services]
    return _clip(f"Services offered by {profile.business_name}:\n" + "\n".join(lines))


def catalog_text(profile: BusinessProfile) -> str:
    parts = [p for p in (menu_text(profile), services_text(profile)) if p]
    if not parts:
        return f"{profile.business_name} has not published a menu or a list of services."
    return _clip("\n\n".join(parts))


# --------------------------------------------------------------------------- question answering
def _best_overlap(question_tokens: set[str], candidates: list[tuple[str, str]]) -> tuple[float, str]:
    """``candidates`` are (searchable text, rendered answer). Returns (score, answer)."""
    best = (0.0, "")
    for haystack, rendered in candidates:
        tokens = set(_tokens(haystack))
        if not tokens:
            continue
        score = len(question_tokens & tokens) / (len(question_tokens) ** 0.5 * len(tokens) ** 0.25)
        if score > best[0]:
            best = (score, rendered)
    return best


def answer_question(profile: BusinessProfile, capabilities: list[Capability], question: str) -> Answer:
    question = question[:MAX_QUESTION_CHARS]
    if is_transaction_request(question):
        return Answer(UNSUPPORTED_TRANSACTION_TEXT, None, unsupported=True)

    allowed = set(capabilities)
    q_tokens = set(_tokens(question))
    words = set(_WORD.findall(question.lower()))

    if Capability.FAQ in allowed and q_tokens:
        score, rendered = _best_overlap(q_tokens, [(f.question, f.answer) for f in profile.faq])
        if score >= 0.8:
            return Answer(_clip(rendered), Capability.FAQ)

    if q_tokens:
        items: list[tuple[str, str, Capability]] = []
        if Capability.MENU_CATALOG in allowed:
            items += [
                (m.name, _item_line(m.name, m.description, m.price), Capability.MENU_CATALOG)
                for m in profile.menu_items
            ]
        if Capability.SERVICES_CATALOG in allowed:
            items += [
                (s.name, _item_line(s.name, s.description, s.price), Capability.SERVICES_CATALOG)
                for s in profile.services
            ]
        hits = [(rendered, cap) for name, rendered, cap in items if set(_tokens(name)) & q_tokens]
        if 0 < len(hits) <= 5:
            body = "\n".join(rendered for rendered, _ in hits)
            return Answer(_clip(f"From {profile.business_name}:\n{body}"), hits[0][1])

    for capability, keywords in _INTENT_KEYWORDS.items():
        if capability in allowed and words & set(keywords):
            if capability is Capability.HOURS:
                return Answer(hours_text(profile), capability)
            if capability is Capability.LOCATION:
                return Answer(location_text(profile), capability)
            return Answer(catalog_text(profile), capability)

    if words & {"phone", "call", "email", "contact", "reach", "website"}:
        contact = contact_text(profile)
        if contact:
            return Answer(f"Contact {profile.business_name}: {contact}", Capability.BUSINESS_INFORMATION)

    return Answer(summary_text(profile), Capability.BUSINESS_INFORMATION)
