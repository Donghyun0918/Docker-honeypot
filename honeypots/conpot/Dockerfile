FROM python:3.11-slim

RUN mkdir -p /var/log/conpot

COPY honeypot.py /honeypot.py

EXPOSE 102 502 161/udp

CMD ["python", "/honeypot.py"]
