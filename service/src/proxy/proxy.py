import argparse
import asyncio
import socket
import logging
import time
from email.utils import formatdate
from typing import Callable, Dict, Optional
import re
import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    DataReceived,
    H3Event,
    HeadersReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived, ProtocolNegotiated, QuicEvent
from aioquic.tls import SessionTicket

from parse import parseConfig, proxy_config

HttpConnection = H3Connection

SERVER_NAME = "aioquic/" + aioquic.__version__


class HttpRequestHandler:
    def __init__(
        self,
        *,
        authority: bytes,
        connection: HttpConnection,
        protocol: QuicConnectionProtocol,
        scope: Dict,
        stream_ended: bool,
        stream_id: int,
        transmit: Callable[[], None],
    ) -> None:
        self.authority = authority
        self.connection = connection
        self.protocol = protocol
        self.queue: asyncio.Queue[Dict] = asyncio.Queue()
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit

        if stream_ended:
            self.queue.put_nowait({"type": "http.request"})

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, DataReceived):
            self.queue.put_nowait(
                {
                    "type": "http.request",
                    "body": event.data,
                    "more_body": not event.stream_ended,
                }
            )
        elif isinstance(event, HeadersReceived) and event.stream_ended:
            self.queue.put_nowait(
                {"type": "http.request", "body": b"", "more_body": False}
            )

    async def run(self) -> None:
        self.stTime = time.perf_counter()
        raw_path = self.scope["raw_path"].decode().strip()
        for denyRule in proxy_config["denyRules"]:
            if denyRule["path"].match(raw_path):
                await self.ans(denyRule["if_match_code"].encode(), b"proxy deny rule", {}, denyRule["if_match_body"].encode())
                return
        method = self.scope["method"]
        receivedBody = b""
        try:
            async with asyncio.timeout(proxy_config["read_timeout"]):
                receivedMsg = await self.receive()
                if "body" in receivedMsg:
                    receivedBody += receivedMsg["body"]
                while "more_body" in receivedMsg and receivedMsg["more_body"]:
                    receivedMsg = await self.receive()
                    if "body" in receivedMsg:
                        receivedBody += receivedMsg["body"]
        except Exception as e:
            self.protocol._quic._logger.error(f"Exception (receiving body): {e}")
            await self.ans(b"400", b"Bad request.....", {}, b"")
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(proxy_config["connect_timeout"])
            sock.connect((proxy_config["upstream"].hostname, proxy_config["upstream"].port))
            requestHeaders = ""
            body = receivedBody.decode()
            for headerName, headerValue in self.scope["headers"]:
                requestHeaders += headerName.decode() + ": " + headerValue.decode() + "\r\n"
            requestHeaders += "Connection: close\r\n"
            request = f"{method} {raw_path} HTTP/1.1\r\n{requestHeaders}\r\n{body}".encode()
            sent = 0
            sock.settimeout(proxy_config["write_timeout"])
            while sent < len(request):
                sent = sent + sock.send(request[sent:])
            response = b""
        except Exception as e:
            self.protocol._quic._logger.error(f"Exception(send request): {e}")
            await self.ans(b"503", b"Service unavailable", {}, b"")
            return
        try:
            sock.settimeout(proxy_config["read_timeout"])
            while True:
                chunk = sock.recv(proxy_config["read_buffer_size"])
                if len(chunk) == 0:
                    sock.close()
                    break
                response = response + chunk
        except socket.timeout as e:
            self.protocol._quic._logger.error(f"Exception(receive response): {e}")
            await self.ans(b"503", b"Service unavailable", {}, b"")
            return
        try:
            top, body = response.split(b"\r\n\r\n", maxsplit=1)
            firstLine, responseHeadersRawNoSplit = top.split(b"\r\n", maxsplit=1)
            responseHeadersRaw = responseHeadersRawNoSplit.split(b"\r\n")
            _, code, msgCode = firstLine.split(b" ", maxsplit=2)
            responseHeaders = []
            for responseHeader in responseHeadersRaw:
                k, v = responseHeader.split(b": ")
                responseHeaders.append((k.lower(), v))
            await self.ans(code, msgCode, responseHeaders, body)
        except Exception as e:
            self.protocol._quic._logger.error(f"Exception(send response): {e} {response}")
            await self.ans(b"503", b"Service unavailable", {}, b"")
            return
        

    async def ans(self, code, msgCode, responseHeaders, body):
        await self.send({"type": "http.response.start", "status": code + b" " + msgCode, "headers": responseHeaders})
        await self.send({"type": "http.response.body", "body": body})
        self.fnTime = time.perf_counter()
        self.protocol._quic._logger.info(f"Request took {str((self.fnTime - self.stTime)*1000)} ms")

    async def receive(self) -> Dict:
        return await self.queue.get()

    async def send(self, message: Dict) -> None:
        if message["type"] == "http.response.start":
            self.connection.send_headers(
                stream_id=self.stream_id,
                headers=[
                    (b":status", str(message["status"]).encode()),
                    (b"server", SERVER_NAME.encode()),
                    (b"date", formatdate(time.time(), usegmt=True).encode()),
                ]
                + [(k, v) for k, v in message["headers"]],
            )
        elif message["type"] == "http.response.body":
            self.connection.send_data(
                stream_id=self.stream_id,
                data=message.get("body", b""),
                end_stream=not message.get("more_body", False),
            )
        self.transmit()


Handler = HttpRequestHandler


class HttpServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[int, Handler] = {}
        self._http: Optional[HttpConnection] = None

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) and event.stream_id not in self._handlers:
            authority = None
            headers = []
            raw_path = b""
            method = ""
            for header, value in event.headers:
                if header == b":authority":
                    authority = value
                    headers.append((b"host", value))
                elif header == b":method":
                    method = value.decode()
                elif header == b":path":
                    raw_path = value
                elif header and not header.startswith(b":"):
                    headers.append((header, value))
            if b"?" in raw_path:
                path_bytes, query_string = raw_path.split(b"?", maxsplit=1)
            else:
                path_bytes, query_string = raw_path, b""
            path = path_bytes.decode()
            self._quic._logger.info("HTTP request %s %s", method, path)

            client_addr = self._http._quic._network_paths[0].addr
            client = (client_addr[0], client_addr[1])

            handler: Handler
            scope: Dict

            scope = {
                "client": client,
                "headers": headers,
                "method": method,
                "path": path,
                "query_string": query_string,
                "raw_path": raw_path,
                "scheme": "https",
                "type": "http",
            }
            handler = HttpRequestHandler(
                authority=authority,
                connection=self._http,
                protocol=self,
                scope=scope,
                stream_ended=event.stream_ended,
                stream_id=event.stream_id,
                transmit=self.transmit,
            )
            self._handlers[event.stream_id] = handler
            asyncio.ensure_future(handler.run())
        elif (
            isinstance(event, (DataReceived, HeadersReceived))
            and event.stream_id in self._handlers
        ):
            handler = self._handlers[event.stream_id]
            handler.http_event_received(event)
        elif isinstance(event, DatagramReceived):
            handler = self._handlers[event.flow_id]
            handler.http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic, enable_webtransport=False)
        elif isinstance(event, DatagramFrameReceived):
            if event.data == b"quack":
                self._quic.send_datagram_frame(b"quack-ack")

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


async def main(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
) -> None:
    server = await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=True
    )
    loop = asyncio.get_running_loop()
    try:
        await loop.create_future()
    finally:
        server.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Steins Gate")
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4433,
        help="listen on the specified port (defaults to 4433)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
    )

    parseConfig("./proxy.conf")

    if proxy_config["upstream"].scheme != "http":
        print("Protocol not supported!")
        exit(1)

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN + ["siduck"],
        is_client=False,
        max_datagram_frame_size=65536,
    )

    configuration.load_cert_chain(args.certificate, args.private_key)

    try:
        asyncio.run(
            main(
                host=args.host,
                port=args.port,
                configuration=configuration,
                session_ticket_store=SessionTicketStore(),
            )
        )
    except KeyboardInterrupt:
        pass
