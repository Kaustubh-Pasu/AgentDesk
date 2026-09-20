#!/bin/sh
# Runs once on first database start. Creates the LEAST-PRIVILEGE role used by the running services:
# DML only, no DDL, not a superuser, cannot alter the append-only audit trigger. Migrations run as the owner role.
set -eu
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set in secrets/postgres.env}"
psql -v ON_ERROR_STOP=1 -v app_password="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE agentdesk_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO agentdesk_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agentdesk_app;
SQL
