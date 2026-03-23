"""
blueshieldaa.network.scanner
----------------------------
Port and host scanning utilities using raw sockets.
"""

import socket
import concurrent.futures
from typing import List, Dict, Optional


class PortScanner:
    """
    Lightweight port scanner using Python sockets.

    Example:
        scanner = PortScanner("192.168.1.1")
        results = scanner.scan(ports=[22, 80, 443])
        print(results)
    """

    def __init__(self, target: str, timeout: float = 1.0):
        """
        Args:
            target: IP address or hostname to scan.
            timeout: Socket timeout in seconds.
        """
        self.target = target
        self.timeout = timeout

    def _scan_port(self, port: int) -> Dict:
        """Attempt a TCP connection to a single port."""
        result = {"port": port, "state": "closed", "service": self._get_service(port)}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                conn = s.connect_ex((self.target, port))
                if conn == 0:
                    result["state"] = "open"
        except (socket.gaierror, OSError):
            result["state"] = "error"
        return result

    def _get_service(self, port: int) -> str:
        """Return well-known service name for a port, if any."""
        try:
            return socket.getservbyport(port)
        except OSError:
            return "unknown"

    def scan(
        self,
        ports: Optional[List[int]] = None,
        port_range: Optional[tuple] = None,
        max_workers: int = 100,
    ) -> List[Dict]:
        """
        Scan a list or range of ports concurrently.

        Args:
            ports: Explicit list of ports to scan.
            port_range: Tuple (start, end) defining a range, e.g. (1, 1024).
            max_workers: Number of concurrent threads.

        Returns:
            List of dicts with keys: port, state, service.
        """
        if ports is None and port_range is None:
            port_range = (1, 1024)

        if port_range:
            ports = list(range(port_range[0], port_range[1] + 1))

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        return sorted(results, key=lambda x: x["port"])

    def open_ports(self, **kwargs) -> List[Dict]:
        """Return only open ports from a scan."""
        return [r for r in self.scan(**kwargs) if r["state"] == "open"]

    def resolve_host(self) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None
