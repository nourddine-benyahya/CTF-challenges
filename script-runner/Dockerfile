FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONPATH=/app \
    FLASK_APP=app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project structure
COPY app/ app/
COPY migrations/ migrations/
COPY config.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh && \
    useradd -m runner && \
    chown -R runner:runner /app && \
    mkdir -p /app/uploads && \
    chmod -R 755 /app

USER runner

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]