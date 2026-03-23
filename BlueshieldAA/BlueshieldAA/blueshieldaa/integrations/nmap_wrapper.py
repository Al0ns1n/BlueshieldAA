"""
blueshieldaa.integrations.nmap_wrapper
----------------------------------------
Wrapper around nmap for advanced host and service discovery.
Requires: nmap installed on the system + pip install python-nmap
"""

from typing import Dict, List, Optional


class NmapScanner:
    """
    Wrapper around python-nmap for structured scan results.

    Example:
        scanner = NmapScanner()
        results = scanner.scan("192.168.1.1", arguments="-sV -p 22,80,443")
        print(results)
    """

    def __init__(self):
        try:
            import nmap
            self._nm = nmap.PortScanner()
        except ImportError:
            raise ImportError(
                "python-nmap is required. Install with: pip install python-nmap\n"
                "Also make sure nmap is installed on your system."
            )

    def scan(self, target: str, arguments: str = "-sV") -> Dict:
        """
        Run an nmap scan on a target.

        Args:
            target: IP address, hostname, or CIDR range (e.g. '192.168.1.0/24').
            arguments: nmap arguments string (default: '-sV' for version detection).

        Returns:
            Dict with host info and open ports.
        """
        self._nm.scan(hosts=target, arguments=arguments)
        results = {}

        for host in self._nm.all_hosts():
            results[host] = {
                "state": self._nm[host].state(),
                "hostname": self._nm[host].hostname(),
                "protocols": {},
            }
            for proto in self._nm[host].all_protocols():
                ports = []
                for port, data in self._nm[host][proto].items():
                    ports.append({
                        "port": port,
                        "state": data["state"],
                        "name": data["name"],
                        "product": data.get("product", ""),
                        "version": data.get("version", ""),
                    })
                results[host]["protocols"][proto] = ports

        return results

    def os_detection(self, target: str) -> Optional[str]:
        """
        Attempt OS detection (requires root/sudo).

        Args:
            target: Target IP or hostname.

        Returns:
            OS match string or None.
        """
        self._nm.scan(hosts=target, arguments="-O")
        try:
            matches = self._nm[target]["osmatch"]
            if matches:
                return matches[0]["name"]
        except (KeyError, IndexError):
            pass
        return None

    def ping_sweep(self, cidr: str) -> List[str]:
        """
        Discover live hosts in a subnet using ping scan.

        Args:
            cidr: Network in CIDR notation (e.g. '192.168.1.0/24').

        Returns:
            List of live IP addresses.
        """
        self._nm.scan(hosts=cidr, arguments="-sn")
        return [host for host in self._nm.all_hosts() if self._nm[host].state() == "up"]
