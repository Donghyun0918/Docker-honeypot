FROM python:3.11-slim

# heralding 의존성을 psycopg2-binary로 대체하여 수동 설치
# (heralding setup.py가 psycopg2 소스 빌드를 강제하므로 --no-deps 사용)
RUN pip install --no-cache-dir \
    psycopg2-binary \
    pycryptodome \
    nose \
    aiosmtpd \
    "asyncssh>=2.0.0" \
    pyOpenSSL \
    pyaml \
    pyzmq \
    hpfeeds3 \
    rsa \
    requests \
    pymysql

RUN pip install --no-cache-dir --no-deps heralding

RUN mkdir -p /var/log/heralding /heralding

COPY heralding.yml /heralding/heralding.yml

EXPOSE 80 3306

CMD ["heralding", "-c", "/heralding/heralding.yml"]
