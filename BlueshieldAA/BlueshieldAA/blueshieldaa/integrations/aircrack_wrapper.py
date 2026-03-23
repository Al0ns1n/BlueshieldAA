"""
blueshieldaa.integrations.aircrack_wrapper
--------------------------------------------
Wrapper to invoke aircrack-ng for WPA2 handshake analysis.
For authorized, controlled environments only.
Requires: aircrack-ng installed on the system.
"""

import subprocess
import re
from typing import Optional, Dict


class AircrackWrapper:
    """
    Interface to aircrack-ng for analyzing captured WPA2 handshakes.
    Use ONLY on networks you own or have explicit permission to test.

    Example:
        ac = AircrackWrapper()
        result = ac.crack_handshake(
            capture_file="capture.cap",
            wordlist="/usr/share/wordlists/rockyou.txt",
            bssid="AA:BB:CC:DD:EE:FF"
        )
        print(result)
    """

    AIRCRACK_BIN = "aircrack-ng"

    def check_available(self) -> bool:
        """Check if aircrack-ng is installed on the system."""
        try:
            subprocess.run(
                [self.AIRCRACK_BIN, "--help"],
                capture_output=True,
                timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def crack_handshake(
        self,
        capture_file: str,
        wordlist: str,
        bssid: Optional[str] = None,
        essid: Optional[str] = None,
    ) -> Dict:
        """
        Run aircrack-ng against a captured WPA2 handshake.

        Args:
            capture_file: Path to .cap / .pcap file with handshake.
            wordlist: Path to the wordlist file.
            bssid: Target BSSID (optional, recommended for multi-AP captures).
            essid: Target ESSID (optional).

        Returns:
            Dict with success, key (if found), and raw output.
        """
        cmd = [self.AIRCRACK_BIN, capture_file, "-w", wordlist]
        if bssid:
            cmd += ["-b", bssid]
        if essid:
            cmd += ["-e", essid]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = proc.stdout + proc.stderr
            return self._parse_output(output)
        except subprocess.TimeoutExpired:
            return {"success": False, "key": None, "error": "Timeout", "raw": ""}
        except FileNotFoundError:
            return {
                "success": False,
                "key": None,
                "error": "aircrack-ng not found. Install with: sudo apt install aircrack-ng",
                "raw": "",
            }

    def _parse_output(self, output: str) -> Dict:
        """Parse aircrack-ng stdout to extract the key if found."""
        key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
        if key_match:
            return {"success": True, "key": key_match.group(1), "error": None, "raw": output}
        return {"success": False, "key": None, "error": "Key not found in wordlist", "raw": output}

    def list_networks_in_capture(self, capture_file: str) -> str:
        """
        List networks/handshakes found in a capture file.

        Args:
            capture_file: Path to .cap file.

        Returns:
            Raw text output from aircrack-ng listing.
        """
        try:
            proc = subprocess.run(
                [self.AIRCRACK_BIN, capture_file],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return str(e)
