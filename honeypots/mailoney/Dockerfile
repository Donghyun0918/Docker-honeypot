FROM python:3.11-slim

RUN mkdir -p /var/log/mailoney

COPY honeypot.py /honeypot.py

EXPOSE 25

CMD ["python", "/honeypot.py"]
