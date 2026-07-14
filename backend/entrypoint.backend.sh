#!/bin/sh

set -e

echo "Waiting for PostgreSQL..."

while ! python manage.py check --database default >/dev/null 2>&1
do
    sleep 2
done

echo "PostgreSQL is ready."

echo "Running migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting Gunicorn..."

exec "$@"