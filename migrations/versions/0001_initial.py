"""Initial schema + database-level guards.

Revision ID: 0001_initial
Revises:

The tables are created from the SQLAlchemy metadata as of this revision. On PostgreSQL two guards are added that the
ORM-level checks cannot give on their own:
- ``audit_events`` is append-only (UPDATE/DELETE raise), even for a compromised application role;
- published ``agent_configs`` rows are immutable.
Later schema changes must be written as explicit ``op.*`` migrations.
"""

from alembic import op

from app.models.db import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

# One statement per entry: asyncpg cannot run several statements in a single execute().
_PG_GUARDS = (
    """CREATE OR REPLACE FUNCTION agentdesk_audit_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_events is append-only'; END; $$ LANGUAGE plpgsql""",
    """CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION agentdesk_audit_append_only()""",
    """CREATE OR REPLACE FUNCTION agentdesk_config_immutable() RETURNS trigger AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN RAISE EXCEPTION 'published agent_configs rows are immutable'; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql""",
    """CREATE TRIGGER agent_configs_immutable BEFORE UPDATE ON agent_configs
FOR EACH ROW EXECUTE FUNCTION agentdesk_config_immutable()""",
)


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    if bind.dialect.name == "postgresql":
        for statement in _PG_GUARDS:
            op.execute(statement)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
        op.execute("DROP TRIGGER IF EXISTS agent_configs_immutable ON agent_configs")
        op.execute("DROP FUNCTION IF EXISTS agentdesk_audit_append_only()")
        op.execute("DROP FUNCTION IF EXISTS agentdesk_config_immutable()")
    Base.metadata.drop_all(bind=bind)
