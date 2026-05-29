FROM python:3.12-slim AS api

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libjpeg62-turbo \
    libopenjp2-7 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY scanner ./scanner
COPY platform ./platform

RUN pip install --no-cache-dir ".[platform,browser]"

EXPOSE 8000
CMD ["uvicorn", "platform.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
