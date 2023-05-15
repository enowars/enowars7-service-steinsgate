FROM python:alpine

WORKDIR /app

COPY proxy.py proxy.py
COPY proxy.conf proxy.conf
COPY parse.py parse.py
COPY privkey.pem privkey.pem
COPY key.pem key.pem
COPY cert.pem cert.pem
COPY requirements.txt requirements.txt

RUN apk add --no-cache wget autoconf build-base bsd-compat-headers openssl-dev alpine-sdk

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "proxy.py", "-c", "cert.pem", "-k", "key.pem"]
