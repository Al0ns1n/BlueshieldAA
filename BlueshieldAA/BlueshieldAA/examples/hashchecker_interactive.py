"""
BlueshieldAA - HashChecker Interactivo con VirusTotal
Pide un archivo del sistema, calcula su hash y lo consulta en VirusTotal.
Si no está en VT, ofrece subirlo para analizarlo.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.expanduser("~/Descargas/BlueshieldAA"))

from blueshieldaa.crypto import HashChecker


# ── Configuración ─────────────────────────────────────────────────────────────
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ── VirusTotal: consultar hash ─────────────────────────────────────────────────
def consultar_virustotal(sha256: str) -> dict:
    url = f"{VT_BASE_URL}/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        elif e.code == 429:
            return {"error": "rate_limit"}
        else:
            return {"error": f"http_{e.code}"}
    except Exception as e:
        return {"error": str(e)}


# ── VirusTotal: subir archivo ──────────────────────────────────────────────────
def subir_a_virustotal(ruta: str) -> dict:
    url = f"{VT_BASE_URL}/files"
    nombre = os.path.basename(ruta)
    boundary = "----BlueshieldAABoundary"

    with open(ruta, "rb") as f:
        contenido = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{nombre}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + contenido + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "x-apikey": VT_API_KEY,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


# ── Mostrar resultado ──────────────────────────────────────────────────────────
def mostrar_stats(data: dict):
    stats     = data["data"]["attributes"]["last_analysis_stats"]
    resultados = data["data"]["attributes"]["last_analysis_results"]
    nombre    = data["data"]["attributes"].get("meaningful_name", "desconocido")
    sha256    = data["data"]["id"]

    maliciosos  = stats.get("malicious", 0)
    sospechosos = stats.get("suspicious", 0)
    limpios     = stats.get("undetected", 0)
    total       = sum(stats.values())

    print(f"\n{'=' * 55}")
    print(f"📋 Nombre    : {nombre}")
    print(f"🔗 URL       : https://www.virustotal.com/gui/file/{sha256}")
    print(f"{'=' * 55}")

    if maliciosos == 0 and sospechosos == 0:
        print(f"✅ LIMPIO — {limpios}/{total} motores no detectan nada")
    elif maliciosos > 0:
        print(f"🚨 MALICIOSO — {maliciosos}/{total} motores lo detectan")
    else:
        print(f"⚠️  SOSPECHOSO — {sospechosos}/{total} motores lo marcan")

    if maliciosos > 0 or sospechosos > 0:
        print("\nMotores que lo detectan:")
        for motor, res in resultados.items():
            if res["category"] in ("malicious", "suspicious"):
                amenaza = res.get("result") or "sin nombre"
                print(f"  🔴 {motor:25s} → {amenaza}")


def analizar(sha256: str, ruta: str):
    print("\n🔍 Consultando VirusTotal...")
    data = consultar_virustotal(sha256)

    # Archivo encontrado directamente
    if "error" not in data:
        mostrar_stats(data)
        return

    # Errores
    if data["error"] == "rate_limit":
        print("⚠️  Límite de consultas alcanzado (4/min). Espera un momento.")
        return
    elif data["error"] != "not_found":
        print(f"❌ Error: {data['error']}")
        return

    # No encontrado → ofrecer subida
    print("ℹ️  Este archivo NO está en VirusTotal.")
    print("   → Nunca ha sido analizado o es muy nuevo.")
    print("\n¿Quieres subirlo para analizarlo? (s/n)")
    if input(">>> ").strip().lower() != "s":
        return

    tamaño = os.path.getsize(ruta)
    if tamaño > 32 * 1024 * 1024:
        print("❌ Archivo demasiado grande (límite gratuito: 32 MB)")
        return

    print("⏳ Subiendo archivo a VirusTotal...")
    resultado = subir_a_virustotal(ruta)
    if "error" in resultado:
        print(f"❌ Error al subir: {resultado['error']}")
        return

    print("✅ Subido. Esperando análisis", end="", flush=True)

    # Esperar hasta 90 segundos a que el análisis esté listo
    for _ in range(18):
        time.sleep(5)
        print(".", end="", flush=True)
        data = consultar_virustotal(sha256)
        if "error" not in data:
            print()
            mostrar_stats(data)
            return

    print()
    print("⚠️  El análisis tarda más de lo esperado.")
    print(f"🔗 Consulta en unos minutos: https://www.virustotal.com/gui/file/{sha256}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("🛡️  BlueshieldAA - HashChecker + VirusTotal")
    print("=" * 55)

    if not VT_API_KEY:
        print("\n⚠️  No se detectó API key de VirusTotal.")
        print("   Ejecuta primero:")
        print('   export VT_API_KEY="tu_api_key_aqui"')
        print("\n   Continuando sin VirusTotal (solo hashes)...\n")

    hc = HashChecker()

    while True:
        print("\nEscribe la ruta del archivo (o 'salir'):")
        ruta = input(">>> ").strip()

        if ruta.lower() == "salir":
            print("Saliendo...")
            break

        ruta = os.path.expanduser(ruta)

        if not os.path.exists(ruta):
            print(f"❌ Archivo no encontrado: {ruta}")
            continue

        if not os.path.isfile(ruta):
            print(f"❌ Eso es un directorio, no un archivo.")
            continue

        tamaño = os.path.getsize(ruta)
        print(f"\n📄 Archivo : {ruta}")
        print(f"📦 Tamaño  : {tamaño:,} bytes ({tamaño / 1024:.2f} KB)")

        print("\n⏳ Calculando hashes...")
        try:
            md5    = hc.hash_file(ruta, algorithm="md5")
            sha1   = hc.hash_file(ruta, algorithm="sha1")
            sha256 = hc.hash_file(ruta, algorithm="sha256")
        except PermissionError:
            print("❌ Sin permisos para leer ese archivo.")
            continue
        except Exception as e:
            print(f"❌ Error: {e}")
            continue

        print(f"\n🔑 MD5    : {md5}")
        print(f"🔑 SHA1   : {sha1}")
        print(f"🔑 SHA256 : {sha256}")

        if VT_API_KEY:
            analizar(sha256, ruta)

        print("\n" + "-" * 55)
        print("¿Analizar otro archivo? (s/n)")
        if input(">>> ").strip().lower() != "s":
            print("Saliendo...")
            break


if __name__ == "__main__":
    main()
