"""
examples/demo.py
-----------------
Quick demonstration of BlueshieldAA capabilities.
Run from project root: python examples/demo.py
"""

from blueshieldaa.network import PortScanner
from blueshieldaa.crypto import HashChecker

# ── Hash Checker ────────────────────────────────────────────────────────────
print("=" * 50)
print("🔐 HashChecker Demo")
print("=" * 50)

hc = HashChecker()

suspicious_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
algo = hc.identify_hash(suspicious_hash)
print(f"Hash: {suspicious_hash}")
print(f"Probable algorithm: {algo}")

token = hc.generate_random_token()
print(f"Random secure token: {token}")

all_hashes = hc.hash_all_algorithms("BlueshieldAA")
for algo, digest in all_hashes.items():
    print(f"  {algo:8s} → {digest}")

# ── Port Scanner ─────────────────────────────────────────────────────────────
print()
print("=" * 50)
print("🌐 PortScanner Demo (localhost)")
print("=" * 50)

scanner = PortScanner("127.0.0.1", timeout=0.5)
results = scanner.scan(ports=[22, 80, 443, 8080, 3306, 5432])

for r in results:
    status = "✅ OPEN" if r["state"] == "open" else "❌ closed"
    print(f"  {r['port']:5d}/tcp  {status}  ({r['service']})")

print()
print("Done. BlueshieldAA is ready.")
