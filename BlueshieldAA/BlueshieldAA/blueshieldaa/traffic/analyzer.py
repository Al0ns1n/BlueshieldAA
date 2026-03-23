"""
blueshieldaa.traffic.analyzer
------------------------------
PCAP / network capture analysis using scapy.
Requires: pip install scapy
"""

from typing import List, Dict, Optional
from collections import Counter


class TrafficAnalyzer:
    """
    Analyze .pcap / .pcapng capture files.

    Example:
        analyzer = TrafficAnalyzer("capture.pcap")
        print(analyzer.summary())
        print(analyzer.top_talkers())
    """

    def __init__(self, filepath: str):
        """
        Args:
            filepath: Path to the .pcap or .pcapng file.
        """
        self.filepath = filepath
        self._packets = None

    def _load(self):
        """Lazy-load packets from file."""
        if self._packets is None:
            try:
                from scapy.all import rdpcap
                self._packets = rdpcap(self.filepath)
            except ImportError:
                raise ImportError(
                    "scapy is required for traffic analysis. "
                    "Install it with: pip install scapy"
                )
        return self._packets

    def summary(self) -> Dict:
        """
        Return a high-level summary of the capture.

        Returns:
            Dict with total_packets, protocols, and duration_seconds.
        """
        packets = self._load()
        protocols = Counter()

        for pkt in packets:
            for layer in pkt.layers():
                protocols[layer.__name__] += 1

        first_ts = float(packets[0].time) if packets else 0
        last_ts = float(packets[-1].time) if packets else 0

        return {
            "total_packets": len(packets),
            "protocols": dict(protocols.most_common()),
            "duration_seconds": round(last_ts - first_ts, 4),
            "file": self.filepath,
        }

    def top_talkers(self, top_n: int = 10) -> List[Dict]:
        """
        Return the top N source IPs by packet count.

        Args:
            top_n: Number of top IPs to return.

        Returns:
            List of dicts with ip and packet_count.
        """
        from scapy.all import IP
        packets = self._load()
        src_counter = Counter()

        for pkt in packets:
            if pkt.haslayer(IP):
                src_counter[pkt[IP].src] += 1

        return [
            {"ip": ip, "packet_count": count}
            for ip, count in src_counter.most_common(top_n)
        ]

    def filter_by_protocol(self, protocol: str) -> List:
        """
        Filter packets by protocol layer name.

        Args:
            protocol: e.g. 'TCP', 'UDP', 'DNS', 'HTTP'.

        Returns:
            List of matching scapy packets.
        """
        from scapy.all import TCP, UDP, DNS, ICMP, ARP
        proto_map = {
            "TCP": TCP, "UDP": UDP, "DNS": DNS, "ICMP": ICMP, "ARP": ARP,
        }
        packets = self._load()
        layer = proto_map.get(protocol.upper())
        if layer is None:
            raise ValueError(f"Unsupported protocol: {protocol}. Try: TCP, UDP, DNS, ICMP, ARP")
        return [pkt for pkt in packets if pkt.haslayer(layer)]

    def extract_http_hosts(self) -> List[str]:
        """
        Extract HTTP Host headers from TCP port 80 traffic.

        Returns:
            List of unique hostnames found.
        """
        from scapy.all import TCP, Raw
        packets = self._load()
        hosts = set()

        for pkt in packets:
            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                    for line in payload.split("\r\n"):
                        if line.lower().startswith("host:"):
                            hosts.add(line.split(":", 1)[1].strip())
                except Exception:
                    continue

        return list(hosts)
