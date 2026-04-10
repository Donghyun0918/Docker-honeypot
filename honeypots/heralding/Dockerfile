FROM python:3.9-slim

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

# asyncio deprecated API 패치 (Python 3.9 호환)
RUN python3 -c "p='/usr/local/lib/python3.9/site-packages/heralding/misc/common.py'; c=open(p).read(); c=c.replace('asyncio.Task.all_tasks(loop=loop)','asyncio.all_tasks()'); c=c.replace('asyncio.Task.current_task(loop=loop)','asyncio.current_task()'); c=c.replace('asyncio.Task.all_tasks()','asyncio.all_tasks()'); c=c.replace('asyncio.Task.current_task()','asyncio.current_task()'); open(p,'w').write(c)"

RUN mkdir -p /var/log/heralding /heralding

COPY heralding.yml /heralding/heralding.yml

EXPOSE 80 3306

CMD ["heralding", "-c", "/heralding/heralding.yml"]
