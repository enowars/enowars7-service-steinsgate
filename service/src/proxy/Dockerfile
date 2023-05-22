FROM python:alpine

WORKDIR /app

COPY proxy.py .
COPY proxy.conf .
COPY parse.py .
COPY privkey.pem .
COPY key.pem .
COPY cert.pem .
COPY requirements.txt .

RUN apk add --no-cache wget autoconf build-base bsd-compat-headers openssl-dev alpine-sdk

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "proxy.py", "-c", "cert.pem", "-k", "key.pem"]
