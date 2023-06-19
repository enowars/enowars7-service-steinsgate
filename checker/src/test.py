import asyncio
from http3 import do_post, do_get, do_request_fakepath
import json

import logging
from logging import LoggerAdapter
from urllib.parse import urlencode, quote_plus
import string
import random

ADDRESS = "91.107.214.3"
PORT = 4433

noise_alph = string.ascii_letters + string.digits
def noise(nmin: int, nmax: int) -> str:
    n = random.randint(nmin, nmax)
    return "".join(random.choice(noise_alph) for _ in range(n))

def assert_status_code(logger: LoggerAdapter, path: str, status: str, headers, body, code: int = 200) -> None:
    status = status[2:-1]
    status_code = int(status.split(" ")[0])
    if status_code == code:
        return
    print(f"Bad status code during request at {path}: ({status_code} != {code})\n{body}")
    raise Exception(f"Received {status_code} code at {path} failed")

async def do_login(logger: LoggerAdapter, username: str, password: str) -> None:
    path = "/login"
    payload = {"username":username,"password":password}
    status, headers, body = await do_post(ADDRESS, PORT, path, {}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body)
    try:
        return json.loads(body)["token"]
    except KeyError as k:
        print(f"No token was retrieved when login, {k.msg}")
        raise Exception(f"No token was retrieved when login")
    except (json.JSONDecodeError, TypeError) as k:
        print(f"Error decoding body, {k.msg}")
        raise Exception(f"Error decoding body")
    except Exception as k:
        print(f"Caught another exception, {k.msg}")
    return None


async def do_profile(logger: LoggerAdapter, token: str = None, username: str = None, password: str = None) -> None:
    path = "/profile"
    if token is None:
        token = await do_login(logger, username, password)
    status, headers, body = await do_get(ADDRESS, PORT, path, {"x-token":token})
    assert_status_code(logger, path, status, headers, body)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError) as k:
        print(f"Error decoding body, {k.msg}")
        raise Exception(f"Error decoding body")
    except Exception as k:
        print(f"Caught another exception, {k.msg}")
    return None

async def do_addphone(logger: LoggerAdapter, phone: str, token: str = None, username: str = None, password: str = None) -> None:
    path = "/addphone"
    if token is None:
        token = await do_login(logger, username, password)
    payload = {"phone":phone}
    status, headers, body = await do_post(ADDRESS, PORT, path, {"x-token":token}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body, code=201)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError) as k:
        print(f"Error decoding body, {k.msg}")
        raise Exception(f"Error decoding body")
    except Exception as k:
        print(f"Caught another exception, {k.msg}")

async def do_register(logger: LoggerAdapter, username: str, password: str) -> None:
    path = "/register"
    payload = {"username":username,"password":password}
    status, headers, body = await do_post(ADDRESS, PORT, path, {}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body, code=201)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError) as k:
        print(f"Error decoding body, {k.msg}")
        raise Exception(f"Error decoding body")
    except Exception as k:
        print(f"Caught another exception, {k.msg}")


async def main():
    username, password = noise(10, 20), noise(10, 20)
    logger = logging.getLogger('spam_application')
    print("Oi")
    await do_register(logger, username, password)
    token = await do_login(logger, username, password)
    path = f"/user/user1"
    true_path = "/ HTTP/1.1\r\nHost: localhost\r\n\r\nGET " + path
    status, headers, body = await do_request_fakepath(ADDRESS, PORT, "GET", path, true_path, {"x-token":token}, None)
    assert_status_code(logger, path, status, headers, body, code=200)

loop = asyncio.get_event_loop()
# Blocking call which returns when the display_date() coroutine is done
loop.run_until_complete(main())
loop.close()