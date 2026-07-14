FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libpq-dev \
    libmagic1 \
    libmagic-dev \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*
    
COPY requirements.txt .

EXPOSE 8000

RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY entrypoint.backend.sh /entrypoint.backend.sh
COPY entrypoint.worker.sh /entrypoint.worker.sh

RUN chmod +x /entrypoint.backend.sh /entrypoint.worker.sh

# Run gunicorn by default
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4"]
