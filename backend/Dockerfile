FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dépendances système (psycopg2, Pillow, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Requirements depuis la racine du projet
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --timeout=600 --retries=10 \
    -r /app/requirements.txt

# Copie du backend
COPY backend/ /app/backend/

WORKDIR /app/backend

EXPOSE 8001
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
