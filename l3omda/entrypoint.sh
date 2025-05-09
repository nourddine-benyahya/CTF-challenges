#!/bin/bash
until nc -z db 5432; do
  echo "Waiting for PostgreSQL..."
  sleep 1
done

python -m app.create_roles

exec "$@"