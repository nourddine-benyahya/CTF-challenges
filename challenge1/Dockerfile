# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
RUN pip install --upgrade pip

# Create directory for the app user
RUN mkdir /app
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt /app/
RUN pip install -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Default command: use Gunicorn to serve
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]