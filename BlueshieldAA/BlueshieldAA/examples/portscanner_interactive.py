"""
BlueshieldAA - PortScanner Interactivo
Escanea puertos, muestra versiones de servicios y geolocaliza el objetivo.
"""

import os
import sys
import subprocess
import re
import json
import ipaddress
import urllib.request
import urllib.error

sys.path.insert(0, os.path.expanduser("~/Descargas/BlueshieldAA"))


# ── Colores ───────────────────────────────────────────────────────────────────
VERDE    = "\033[92m"
ROJO     = "\033[91m"
AMARILLO = "\033[93m"
AZUL     = "\033[94m"
CYAN     = "\033[96m"
NEGRITA  = "\033[1m"
RESET    = "\033[0m"


# ── Geolocalización ───────────────────────────────────────────────────────────
def es_ip_privada(objetivo: str) -> bool:
    """Comprueba si la IP es privada o local."""
    try:
        ip = ipaddress.ip_address(objetivo)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False  # Es un dominio, no una IP


def geolocalizarIP(objetivo: str):
    """Consulta ip-api.com y muestra info de geolocalización."""
    print(f"\n{NEGRITA}🌍 Geolocalización{RESET}")
    print(f"{'─' * 60}")

    if es_ip_privada(objetivo):
        print(f"  {AMARILLO}ℹ️  IP privada/local — no se puede geolocalizar{RESET}")
        return

    try:
        url = (
            f"http://ip-api.com/json/{objetivo}"
            f"?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query,lat,lon"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "BlueshieldAA/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"  {ROJO}❌ Error al geolocalizar: {e}{RESET}")
        return

    if data.get("status") != "success":
        print(f"  {ROJO}❌ {data.get('message', 'Error desconocido')}{RESET}")
        return

    es_proxy   = data.get("proxy", False)
    es_hosting = data.get("hosting", False)

    if es_proxy:
        vpn_info = f"{ROJO}⚠️  Sí (VPN/Proxy detectado){RESET}"
    elif es_hosting:
        vpn_info = f"{AMARILLO}⚠️  Servidor/Hosting{RESET}"
    else:
        vpn_info = f"{VERDE}No detectado{RESET}"

    print(f"  🔎 IP        : {CYAN}{data.get('query', objetivo)}{RESET}")
    print(f"  🌍 País      : {data.get('country', 'Desconocido')}")
    print(f"  🏙️  Ciudad    : {data.get('city', 'Desconocida')}, {data.get('regionName', '')}")
    print(f"  🏢 ISP       : {data.get('isp', 'Desconocido')}")
    print(f"  🏛️  Org       : {data.get('org', 'Desconocida')}")
    print(f"  📡 AS        : {data.get('as', 'Desconocido')}")
    print(f"  🔒 VPN/Proxy : {vpn_info}")
    lat = data.get('lat', '')
    lon = data.get('lon', '')
    if lat and lon:
        print(f"  📍 Coords    : {CYAN}{lat}, {lon}{RESET}")
        print(f"  🗺️  Maps      : {AZUL}https://maps.google.com/?q={lat},{lon}{RESET}")


# ── Nmap ──────────────────────────────────────────────────────────────────────
def verificar_nmap():
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except FileNotFoundError:
        return False


def escanear(objetivo: str, puertos: str, intensidad: str) -> str:
    """Ejecuta nmap y devuelve la salida en texto."""
    args_intensidad = {
        "1": ["-sS", "-sV", "--version-intensity", "1"],
        "2": ["-sS", "-sV", "--version-intensity", "5"],
        "3": ["-sS", "-sV", "--version-intensity", "9", "-O",
              "--script=banner,http-title,ssh-hostkey"],
    }

    if puertos.startswith("--top-ports"):
        cmd = ["sudo", "nmap"] + args_intensidad[intensidad] + puertos.split() + [objetivo]
    else:
        cmd = ["sudo", "nmap"] + args_intensidad[intensidad] + ["-p", puertos, objetivo]

    print(f"\n{AZUL}⚙️  Ejecutando:{RESET} {' '.join(cmd)}\n")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return "ERROR: Tiempo de espera agotado."
    except Exception as e:
        return f"ERROR: {e}"


def parsear_y_mostrar(output: str):
    """Parsea la salida de nmap y la muestra de forma bonita."""
    lineas = output.splitlines()
    en_puertos = False

    print(f"\n{NEGRITA}🔍 Resultado del escaneo{RESET}")
    print(f"{'=' * 60}")
    print(f"{NEGRITA}{'PORT':<15} {'STATE':<10} {'SERVICE':<12} VERSION{RESET}")
    print(f"{'=' * 60}")

    for linea in lineas:
        if linea.startswith("Nmap scan report for"):
            host = linea.replace("Nmap scan report for", "").strip()
            print(f"\n{NEGRITA}🎯 Host     : {host}{RESET}")

        elif "Host is up" in linea:
            latencia = re.search(r"\((.*?)\)", linea)
            if latencia:
                print(f"📡 Latencia  : {latencia.group(1)}")

        elif "OS details:" in linea or "Aggressive OS guesses:" in linea:
            os_info = linea.split(":", 1)[1].strip()
            print(f"💻 OS        : {AMARILLO}{os_info}{RESET}")

        elif linea.startswith("PORT"):
            en_puertos = True
            continue

        elif en_puertos and linea.strip() == "":
            en_puertos = False
            print(f"{'─' * 60}")

        elif en_puertos and re.match(r"^\d+/", linea):
            partes = linea.split()
            if len(partes) >= 3:
                puerto   = partes[0]
                estado   = partes[1]
                servicio = partes[2]
                version  = " ".join(partes[3:]) if len(partes) > 3 else ""

                if estado == "open":
                    color, icono = VERDE, "✅"
                elif estado == "closed":
                    color, icono = ROJO, "❌"
                else:
                    color, icono = AMARILLO, "⚠️ "

                print(
                    f"{icono} {color}{puerto:<14}{RESET} "
                    f"{color}{estado:<10}{RESET} "
                    f"{servicio:<12} "
                    f"{AMARILLO}{version}{RESET}"
                )

        elif "|" in linea and not en_puertos:
            print(f"  {AZUL}{linea.strip()}{RESET}")

    open_count     = len(re.findall(r"\bopen\b", output))
    closed_count   = len(re.findall(r"\bclosed\b", output))
    filtered_count = len(re.findall(r"\bfiltered\b", output))

    print(f"\n{NEGRITA}📊 Resumen:{RESET}")
    print(f"  {VERDE}Abiertos  : {open_count}{RESET}")
    print(f"  {ROJO}Cerrados  : {closed_count}{RESET}")
    print(f"  {AMARILLO}Filtrados : {filtered_count}{RESET}")


def pedir_puertos() -> str:
    print(f"\n{NEGRITA}¿Qué puertos quieres escanear?{RESET}")
    print("  1) Top 100 puertos más comunes")
    print("  2) Top 1000 puertos más comunes")
    print("  3) Rango personalizado (ej: 1-65535)")
    print("  4) Puertos específicos (ej: 22,80,443,8080)")
    opcion = input(">>> ").strip()

    if opcion == "1":
        return "--top-ports 100"
    elif opcion == "2":
        return "--top-ports 1000"
    elif opcion == "3":
        return input("Introduce el rango (ej: 1-10000): ").strip()
    elif opcion == "4":
        return input("Introduce los puertos (ej: 22,80,443): ").strip()
    else:
        print("Opción no válida, usando top 100.")
        return "--top-ports 100"


def pedir_intensidad() -> str:
    print(f"\n{NEGRITA}¿Qué nivel de detalle quieres?{RESET}")
    print("  1) Rápido    — versiones básicas")
    print("  2) Normal    — versiones detalladas  (recomendado)")
    print("  3) Completo  — versiones + OS + scripts de info")
    opcion = input(">>> ").strip()
    if opcion in ("1", "2", "3"):
        return opcion
    print("Opción no válida, usando Normal.")
    return "2"


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print(f"{NEGRITA}🛡️  BlueshieldAA - PortScanner Interactivo{RESET}")
    print("=" * 60)

    if not verificar_nmap():
        print(f"{ROJO}❌ nmap no está instalado.{RESET}")
        print("   Instálalo con: sudo apt install nmap")
        sys.exit(1)

    while True:
        print(f"\n{NEGRITA}Introduce la IP o dominio objetivo (o 'salir'):{RESET}")
        objetivo = input(">>> ").strip()

        if objetivo.lower() == "salir":
            print("Saliendo...")
            break

        if not objetivo:
            print("❌ Debes introducir una IP o dominio.")
            continue

        # Geolocalización antes del escaneo
        geolocalizarIP(objetivo)

        puertos    = pedir_puertos()
        intensidad = pedir_intensidad()

        print(f"\n{AMARILLO}⚠️  Escanea solo redes y sistemas que sean tuyos o tengas permiso.{RESET}")
        print(f"{NEGRITA}¿Continuar? (s/n){RESET}")
        if input(">>> ").strip().lower() != "s":
            continue

        print(f"\n⏳ Escaneando {NEGRITA}{objetivo}{RESET}, esto puede tardar unos segundos...")
        output = escanear(objetivo, puertos, intensidad)
        parsear_y_mostrar(output)

        print(f"\n{'─' * 60}")
        print("¿Escanear otro objetivo? (s/n)")
        if input(">>> ").strip().lower() != "s":
            print("Saliendo...")
            break


if __name__ == "__main__":
    main()
