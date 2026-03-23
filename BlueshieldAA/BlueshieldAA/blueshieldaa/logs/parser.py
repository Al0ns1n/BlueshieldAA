"""
blueshieldaa.logs.parser
--------------------------
Log parsing and alert detection for common log formats.
Supports: syslog, auth.log, Apache/Nginx access logs.
"""

import re
from typing import List, Dict, Optional
from pathlib import Path
from collections import Counter
from datetime import datetime


# Common patterns
PATTERNS = {
    "ssh_failed": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    "ssh_accepted": re.compile(r"Accepted password for (\S+) from (\S+)"),
    "ssh_invalid_user": re.compile(r"Invalid user (\S+) from (\S+)"),
    "sudo_command": re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.+)"),
    "apache_access": re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    ),
}


class LogParser:
    """
    Parse and analyze system and web server log files.

    Example:
        parser = LogParser("/var/log/auth.log")
        print(parser.failed_ssh_attempts())
        print(parser.brute_force_candidates(threshold=10))
    """

    def __init__(self, filepath: str):
        """
        Args:
            filepath: Path to the log file to analyze.
        """
        self.filepath = Path(filepath)
        self._lines: Optional[List[str]] = None

    def _read(self) -> List[str]:
        """Lazy-load lines from file."""
        if self._lines is None:
            with open(self.filepath, "r", errors="ignore") as f:
                self._lines = f.readlines()
        return self._lines

    def failed_ssh_attempts(self) -> List[Dict]:
        """
        Extract all failed SSH login attempts from auth.log.

        Returns:
            List of dicts with user and source_ip.
        """
        results = []
        for line in self._read():
            match = PATTERNS["ssh_failed"].search(line)
            if match:
                results.append({
                    "user": match.group(1),
                    "source_ip": match.group(2),
                    "raw": line.strip(),
                })
        return results

    def successful_ssh_logins(self) -> List[Dict]:
        """
        Extract successful SSH logins.

        Returns:
            List of dicts with user and source_ip.
        """
        results = []
        for line in self._read():
            match = PATTERNS["ssh_accepted"].search(line)
            if match:
                results.append({
                    "user": match.group(1),
                    "source_ip": match.group(2),
                    "raw": line.strip(),
                })
        return results

    def brute_force_candidates(self, threshold: int = 5) -> List[Dict]:
        """
        Identify IPs with failed SSH attempts above a threshold.

        Args:
            threshold: Minimum number of failed attempts to flag.

        Returns:
            List of dicts with source_ip and attempt_count, sorted descending.
        """
        attempts = self.failed_ssh_attempts()
        counter = Counter(a["source_ip"] for a in attempts)
        return [
            {"source_ip": ip, "attempt_count": count}
            for ip, count in counter.most_common()
            if count >= threshold
        ]

    def sudo_commands(self) -> List[Dict]:
        """
        Extract all sudo commands executed from auth.log.

        Returns:
            List of dicts with user and command.
        """
        results = []
        for line in self._read():
            match = PATTERNS["sudo_command"].search(line)
            if match:
                results.append({
                    "user": match.group(1),
                    "command": match.group(2).strip(),
                    "raw": line.strip(),
                })
        return results

    def parse_apache_access(self) -> List[Dict]:
        """
        Parse Apache/Nginx combined access log format.

        Returns:
            List of dicts with ip, time, method, path, status, size.
        """
        results = []
        for line in self._read():
            match = PATTERNS["apache_access"].match(line)
            if match:
                results.append(match.groupdict())
        return results

    def http_error_summary(self) -> Dict[str, int]:
        """
        Count HTTP status codes from an Apache/Nginx access log.

        Returns:
            Dict mapping status code to count.
        """
        entries = self.parse_apache_access()
        return dict(Counter(e["status"] for e in entries).most_common())

    def search(self, keyword: str, case_sensitive: bool = False) -> List[str]:
        """
        Search lines containing a keyword.

        Args:
            keyword: String to search for.
            case_sensitive: Whether the search is case-sensitive.

        Returns:
            Matching lines.
        """
        lines = self._read()
        if not case_sensitive:
            keyword = keyword.lower()
            return [l.strip() for l in lines if keyword in l.lower()]
        return [l.strip() for l in lines if keyword in l]
