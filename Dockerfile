# Works on Raspberry Pi (64-bit) and x86_64
FROM python:3.11-slim

# Minimal libs for OpenCV wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 tesseract-ocr && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy sources
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY sensitive.yaml ./sensitive.yaml

ENV PORT=8000
EXPOSE 8000

CMD ["python", "app/main.py"]