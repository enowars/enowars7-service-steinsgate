# enowars7-service-steinsgate

## Vulnerability

The vulnerability is an inconsistent interpretation of HTTP requests in the translation of HTTP/3 to HTTP/1.1. The reverse proxy has deny rules and there are multiple ways of exploiting it, one way is to send a request like this:


```
:method "GET"
:path "/ HTTP/1.1\r\n\r\nGET /users/{id}"
...
```

## Possible mitigations

* Implement HTTP3 in the backend (hard?)
* Fix the inconsistent interpretation of HTTP (medium because it can lead to other vulnerabilities)
* Use another reverse proxy (nginx) to do the translation (maybe easy)

## Check before release

* We need to be carefull because someone could smuggle the checker's requests. Is this considered attacking infrastructure?
