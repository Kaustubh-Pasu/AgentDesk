"""Seed the safe demo business agent (``demo.${BASE_DOMAIN}``) so the gates are testable before any import.

The demo tenant is ordinary data served by the same generic runtime as every generated tenant. It is
owned by a permanently disabled system account that nobody can log in to.
"""

from __future__ import annotations

import secrets

from sqlalchemy import select

from app.models.db import AgentConfig, Database, Role, Tenant, TenantState, User, utcnow
from app.models.schemas import (
    BusinessCategory,
    BusinessProfile,
    FaqItem,
    HoursEntry,
    MenuItem,
    ServiceItem,
)
from app.security.passwords import hash_password
from app.settings import Settings

SYSTEM_USER_LOCAL_PART = "system-demo-owner"


def demo_profile() -> BusinessProfile:
    return BusinessProfile(
        business_name="Hokie Bean Cafe (demo)",
        description=(
            "A fictional neighbourhood coffee shop used to demonstrate Agent Desk. "
            "It serves espresso drinks, pastries and light lunches, and hosts weekly study nights."
        ),
        category=BusinessCategory.RESTAURANT,
        address="123 Demo Street, Blacksburg, VA 24060",
        hours=[
            HoursEntry(days="Monday-Friday", hours="7:00 AM - 7:00 PM"),
            HoursEntry(days="Saturday", hours="8:00 AM - 5:00 PM"),
            HoursEntry(days="Sunday", hours="Closed"),
        ],
        services=[
            ServiceItem(
                name="Catering",
                description="Coffee and pastry trays for events of 10-60 people.",
                price="from $45",
            ),
            ServiceItem(
                name="Study night room", description="Free reservable back room on Wednesday evenings."
            ),
        ],
        menu_items=[
            MenuItem(name="Espresso", price="$3.00", section="Coffee"),
            MenuItem(
                name="Oat milk latte",
                description="Double shot with steamed oat milk.",
                price="$5.25",
                section="Coffee",
            ),
            MenuItem(name="Cold brew", description="Steeped for 18 hours.", price="$4.50", section="Coffee"),
            MenuItem(name="Almond croissant", price="$4.25", section="Bakery"),
            MenuItem(
                name="Turkey pesto panini",
                description="Served with kettle chips.",
                price="$9.50",
                section="Lunch",
            ),
        ],
        faq=[
            FaqItem(question="Do you have wifi?", answer="Yes, free wifi is available for customers."),
            FaqItem(
                question="Do you offer vegan options?",
                answer="Yes: oat and soy milk, and a vegan muffin daily.",
            ),
        ],
    )


async def seed_demo_agent(db: Database, settings: Settings) -> bool:
    """Idempotent. Returns True if the demo tenant was created by this call."""
    async with db.session() as session:
        existing = (
            await session.execute(select(Tenant).where(Tenant.agent_host == settings.demo_host))
        ).scalar_one_or_none()
        if existing is not None:
            return False
        email = f"{SYSTEM_USER_LOCAL_PART}@{settings.base_domain}"
        owner = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if owner is None:
            owner = User(
                email=email,
                password_hash=hash_password(
                    secrets.token_urlsafe(48)
                ),  # random, discarded: no login possible
                role=Role.OWNER,
                disabled_at=utcnow(),
            )
            session.add(owner)
            await session.flush()
        profile = demo_profile()
        tenant = Tenant(
            owner_id=owner.id,
            display_name=profile.business_name,
            agent_host=settings.demo_host,
            state=TenantState.DEPLOYED,
            current_version=settings.ans_agent_version,
            is_demo=True,
        )
        session.add(tenant)
        await session.flush()
        session.add(
            AgentConfig(
                tenant_id=tenant.id,
                version=settings.ans_agent_version,
                profile=profile.model_dump(mode="json"),
                allowed_capabilities=[c.value for c in profile.derived_capabilities()],
                content_hash=profile.content_hash(),
                published_at=utcnow(),
            )
        )
        await session.commit()
        return True
