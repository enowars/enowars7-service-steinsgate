FROM python:alpine

WORKDIR /app

COPY proxy.py .
COPY proxy.conf .
COPY parse.py .
COPY requirements.txt .

RUN apk add --no-cache wget autoconf build-base bsd-compat-headers openssl-dev alpine-sdk

RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "proxy.py", "-c", "cert.pem", "-k", "key.pem"]
