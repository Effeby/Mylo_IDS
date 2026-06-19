FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --timeout=600 --retries=10 \
    -r /app/requirements.txt \
    --extra-index-url https://pypi.org/simple \
    && pip uninstall -y nvidia-nccl-cu12 nvidia-cublas-cu12 \
       nvidia-cuda-cupti-cu12 nvidia-cuda-nvrtc-cu12 \
       nvidia-cuda-runtime-cu12 nvidia-cudnn-cu12 \
       nvidia-curand-cu12 nvidia-cusolver-cu12 \
       nvidia-cusparse-cu12 nvidia-cufft-cu12 \
       2>/dev/null || true
       
COPY backend/ /app/backend/
WORKDIR /app/backend
EXPOSE 8001
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]

