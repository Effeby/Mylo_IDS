FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copier les requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le dossier ml
COPY ml/ ./ml/
COPY .env.capture* ./

CMD ["python", "ml/capture.py"]