FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DECOY_HOST=0.0.0.0 \
    DECOY_LOG=/var/log/deception/interactions.jsonl

RUN useradd --create-home --uid 10001 decoy
WORKDIR /app
COPY deception_farm.py /app/deception_farm.py
RUN mkdir -p /var/log/deception && chown -R decoy:decoy /app /var/log/deception
USER decoy

EXPOSE 8080 2222 2121 2323
CMD ["python", "/app/deception_farm.py"]
