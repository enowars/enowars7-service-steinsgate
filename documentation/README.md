# SteinsGate Docs

## Information

The service is made of 3 containers, which are running in the same network.

* Backend: This is the main service, we have a login/register functionality, we can add phones to a phonebook and notes to a notebook. All notes are encrypted but phones are not.
* Proxy: This service is  responsible to receive all HTTP3 requests and fallback to a HTTP1 backend, it also implements some security for slow attacks and deny of paths that are internal for the backend only.
* Interface: This service is just an interface to a client.

## How to setup the service?

`docker compose up --build -d`

## Vulnerability 1 - HTTP Request Smuggling

The vulnerability is an inconsistent interpretation of HTTP requests in the translation of HTTP/3 to HTTP/1.1. The reverse proxy has deny rules and there are multiple ways of exploiting it, one way is to send a request like this:

```
:method "GET"
:path "/ HTTP/1.1\r\n\r\nGET /users/{id}"
...
```

### Possible mitigations

* Implement HTTP3 in the backend (hard?)
* Fix the inconsistent interpretation of HTTP (medium because it can lead to other vulnerabilities)
* Use another reverse proxy (nginx) to do the translation (medium because it is not easy to new players, but might be for experienced players)
* Deny Everything that has /users in request. (easy?)

### Check before release

* ~~We need to be carefull because someone could smuggle the checker's requests. Is this considered attacking infrastructure?~~ This is not possible because sockets are not reused, we create a new one for each http3 request.

## Vulnerability 2 - Anomalous Curve

We are given a encrypted note system, each note is AES encrypted with the private key of a user. The issue is that the curve used to generate the public key is anomalous, so anyone can transfer the problem from a DLP in a multiplicative group to a DLP in a additive group in the p-adic field of the prime that generates the curve group. This is known as Smart Attack. For reference https://arxiv.org/abs/1702.07107

### Possible mitigations

Use a standard curve or one such that the order does not divide the prime that generates the base group. For reference https://neuromancer.sk/std/nist/P-256

