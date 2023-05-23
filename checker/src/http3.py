import asyncio
import logging
import ssl
import time
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import CipherSuite, SessionTicket

logger = logging.getLogger("client")

HttpConnection = H3Connection

USER_AGENT = "aioquic/" + aioquic.__version__

class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme

class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url

class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._http = H3Connection(self._quic)

    async def send_no_body(self, url: str, headers: Optional[Dict] = None, method: Optional[str] = None) -> Deque[H3Event]:
        return await self._request(
            HttpRequest(method=method, url=URL(url), headers=headers)
        )

    async def send_with_body(
        self, url: str, data: bytes, headers: Optional[Dict] = None, method: Optional[str] = None
    ) -> Deque[H3Event]:
        return await self._request(
            HttpRequest(method=method, url=URL(url),
                        content=data, headers=headers)
        )

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(
                        self._request_events.pop(stream_id))

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
                (b"user-agent", USER_AGENT.encode()),
            ]
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


async def perform_http_request(
    client: HttpClient,
    url: str,
    headers: dict,
    method: str,
    data: Optional[str],
    include: bool,
) -> None:
    # perform request
    start = time.time()
    if data is not None:
        method = "POST" if method == None else method
        data_bytes = data.encode()
        http_events = await client.send_with_body(
            url,
            data=data_bytes,
            headers=dict({
                "content-length": str(len(data_bytes)) if "content-length" not in headers else headers["content-length"],
                "content-type": "application/x-www-form-urlencoded" if "content-type" not in headers else headers["content-type"],
            }, **headers),
            method=method
        )
    else:
        method = "GET" if method == None else method
        http_events = await client.send_no_body(url, headers=headers, method=method)
    elapsed = time.time() - start

    # print speed
    octets = 0
    for http_event in http_events:
        if isinstance(http_event, DataReceived):
            octets += len(http_event.data)
    logger.info(
        "Response received for %s %s : %d bytes in %.1f s (%.3f Mbps)"
        % (method, urlparse(url).path, octets, elapsed, octets * 8 / elapsed / 1000000)
    )

    out = b""
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                out += headers + b"\r\n"
        elif isinstance(http_event, DataReceived):
            out += http_event.data
    return out


def process_http_pushes(
    client: HttpClient,
    include: bool,
) -> None:
    for _, http_events in client.pushes.items():
        method = ""
        octets = 0
        path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info("Push received for %s %s : %s bytes", method, path, octets)
        out = b""
        for http_event in http_events:
            if isinstance(http_event, HeadersReceived) and include:
                headers = b""
                for k, v in http_event.headers:
                    headers += k + b": " + v + b"\r\n"
                if headers:
                    out += headers + b"\r\n"
            elif isinstance(http_event, DataReceived):
                out += http_event.data
        return out


async def do_get(host, port, path, headers={}):
    return await do_request(host, port, "GET", path, headers, None)

async def do_post(host, port, path, headers={}, data=None):
    return await do_request(host, port, "POST", path, headers, data)

async def do_request(host, port, method, path, headers, data):
    async with connect(
        host,
        port,
        configuration=QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
        ),
        create_protocol=HttpClient,
        local_port=0,
        wait_connected=False,
    ) as client:
        client = cast(HttpClient, client)
        res = await perform_http_request(
            include=True,
            client=client,
            url=f"https://{host}:{port}{path}",
            data=data,
            headers=headers,
            method=method
        )
        # process http pushes
        res2 = process_http_pushes(client=client, include=True)
        if res2 is not None:
            res += res2
        client._quic.close(error_code=ErrorCode.H3_NO_ERROR)
        status, part2 = res.decode().split("\r\n", 1)
        status = status.split(": ", 1)[1]
        recHeaders, recBody = part2.split("\r\n\r\n", 1)
        return status, recHeaders, recBody
