"""HTTP transport that connects only to a pre-resolved set of IP addresses.

The request URL and urllib3 pool keep the original hostname, so HTTP Host, TLS
SNI, and certificate hostname checks remain correct. Only the TCP connection's
socket destination is pinned to one of the already validated IP addresses.
"""

import ipaddress
import socket
import threading
from typing import Iterable, Tuple
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter
from requests.exceptions import InvalidProxyURL, InvalidURL
from requests.utils import select_proxy
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util.connection import create_connection


def _normalize_addresses(addresses: Iterable[str]) -> Tuple[str, ...]:
    normalized = []
    for address in addresses:
        try:
            candidate = ipaddress.ip_address(address)
        except (TypeError, ValueError) as exc:
            raise ValueError("Pinned destinations must be IP addresses") from exc
        canonical = str(candidate)
        if canonical not in normalized:
            normalized.append(canonical)
    if not normalized:
        raise ValueError("At least one validated destination address is required")
    return tuple(normalized)


class _PinnedConnectionMixin:
    """Connection mixin that skips DNS and dials only validated IP literals."""

    def __init__(self, *args, pinned_addresses, **kwargs):
        self._pinned_addresses = _normalize_addresses(pinned_addresses)
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        last_error = None
        saw_timeout = False
        allowed_peers = {ipaddress.ip_address(address) for address in self._pinned_addresses}

        for address in self._pinned_addresses:
            try:
                sock = create_connection(
                    (address, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except socket.timeout as exc:
                last_error = exc
                saw_timeout = True
                continue
            except OSError as exc:
                last_error = exc
                continue

            try:
                peer_address = ipaddress.ip_address(sock.getpeername()[0])
            except (OSError, ValueError):
                sock.close()
                last_error = OSError("Could not verify the connected peer address")
                continue

            if peer_address not in allowed_peers:
                sock.close()
                last_error = OSError("Connected peer did not match a validated destination")
                continue
            return sock

        message = f"Could not connect to a validated destination for {self.host}: {last_error}"
        if saw_timeout:
            raise ConnectTimeoutError(self, message) from last_error
        raise NewConnectionError(self, message) from last_error


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection

    def __init__(self, *args, pinned_addresses, **kwargs):
        self._pinned_addresses = _normalize_addresses(pinned_addresses)
        super().__init__(*args, pinned_addresses=self._pinned_addresses, **kwargs)


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection

    def __init__(self, *args, pinned_addresses, **kwargs):
        self._pinned_addresses = _normalize_addresses(pinned_addresses)
        super().__init__(*args, pinned_addresses=self._pinned_addresses, **kwargs)


class PinnedAddressAdapter(HTTPAdapter):
    """Requests adapter that retains the hostname but pins the socket destination."""

    def __init__(self, host: str, port: int, addresses: Iterable[str], **kwargs):
        if not isinstance(host, str) or not host:
            raise ValueError("A target hostname is required")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Target port must be between 1 and 65535")
        self.host = host.rstrip(".").lower()
        self.port = port
        self.addresses = _normalize_addresses(addresses)
        self._pools = []
        self._pools_lock = threading.Lock()
        super().__init__(**kwargs)

    def _connection_pool(self, url: str, proxies=None):
        proxy = select_proxy(url, proxies or {})
        if proxy:
            # A proxy would make the proxy, not this process, resolve/connect to
            # the target hostname and would defeat destination pinning.
            raise InvalidProxyURL("Proxies are not supported for pinned target connections")

        try:
            parsed = urlsplit(url)
            target_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise InvalidURL("Invalid URL for pinned target connection") from exc

        target_host = parsed.hostname or ""
        if target_host.rstrip(".").lower() != self.host or target_port != self.port:
            raise InvalidURL("Pinned connection cannot be reused for a different target")
        if parsed.scheme.lower() not in {"http", "https"}:
            raise InvalidURL("Pinned connections support only HTTP(S)")

        pool_type = _PinnedHTTPSConnectionPool if parsed.scheme.lower() == "https" else _PinnedHTTPConnectionPool
        pool = pool_type(
            host=self.host,
            port=self.port,
            pinned_addresses=self.addresses,
            maxsize=self._pool_maxsize,
            block=self._pool_block,
        )
        with self._pools_lock:
            self._pools.append(pool)
        return pool

    def get_connection(self, url, proxies=None):
        """Compatibility path used by Requests before 2.32.2."""
        return self._connection_pool(url, proxies)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        """Connection path used by current Requests releases."""
        return self._connection_pool(request.url, proxies)

    def close(self):
        with self._pools_lock:
            pools, self._pools = self._pools, []
        for pool in pools:
            pool.close()
        super().close()
