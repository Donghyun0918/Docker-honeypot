FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir opencanary

RUN mkdir -p /var/log/opencanary /etc/opencanaryd

COPY opencanary.conf /root/.opencanary.conf
COPY opencanary.conf /etc/opencanaryd/opencanary.conf

EXPOSE 21 3389 5900

CMD ["sh", "-c", "rm -f /root/twistd.pid /tmp/twistd.pid && opencanaryd --dev"]
