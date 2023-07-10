FROM python:3.10-alpine AS builder

WORKDIR /app

RUN apk add --no-cache wget autoconf build-base bsd-compat-headers openssl-dev alpine-sdk

COPY requirements.txt /app
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt

COPY . /app

ENTRYPOINT ["python3"]
CMD ["app.py"]