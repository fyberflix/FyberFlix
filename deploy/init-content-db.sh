#!/bin/sh
# Creates the content database if it does not exist (Postgres only auto-creates the first one).
set -eu
export PGPASSWORD="$POSTGRES_PASSWORD"
URL="postgres://fyber@postgres:5432/fyberflix_auth"
if psql "$URL" -tAc "SELECT 1 FROM pg_database WHERE datname='fyberflix_content'" | grep -q 1; then
  echo "fyberflix_content already exists"
else
  psql "$URL" -c "CREATE DATABASE fyberflix_content"
  echo "created fyberflix_content"
fi
