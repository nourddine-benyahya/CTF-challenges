#!/bin/bash

# Apply database migrations
flask db upgrade

# Start server
if [ "$FLASK_ENV" = "production" ]; then
    exec gunicorn -b :5000 --access-logfile - --error-logfile - "app:create_app()"
else
    exec flask run --host=0.0.0.0 --port=5000
fi