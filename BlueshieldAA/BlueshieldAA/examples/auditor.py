"""
BlueshieldAA - Auditor de Seguridad Local
Analiza tu sistema Linux y da recomendaciones reales de seguridad.
"""

import os
import sys
import subprocess
import re
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/Descargas/BlueshieldAA"))


# ── Colores ───────────────────────────────────────────────────────────────────
VERDE    = "\033[92m"
ROJO     = "\033[91m"
AMARILLO = "\033[93m"
AZUL     = "\033[94m"
CYAN     = "\033[96m"
NEGRITA  = "\033[1m"
RESET    = "\033[0m"
GRIS     = "\033[90m"


# ── Helpers ───────────────────────────────────────────────────────────────────
def cmd(comando: str) -> str:
    """Ejecuta un comando y devuelve la salida."""
    try:
        result = subprocess.run(
            comando, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def cmd_ok(comando: str) -> bool:
    """Devuelve True si el comando tiene exit code 0."""
    try:
        result = subprocess.run(
            comando, shell=True, capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def leer_archivo(ruta: str) -> str:
    try:
        return Path(ruta).read_text(errors="ignore")
    except Exception:
        return ""


# ── Sistema de puntuación ─────────────────────────────────────────────────────
hallazgos = []

def check(nivel: str, titulo: str, detalle: str, recomendacion: str, puntos: int):
    """Registra un hallazgo."""
    hallazgos.append({
        "nivel": nivel,
        "titulo": titulo,
        "detalle": detalle,
        "recomendacion": recomendacion,
        "puntos": puntos,
    })

ICONOS = {
    "CRITICO": f"{ROJO}🔴 CRÍTICO {RESET}",
    "ALTO":    f"{AMARILLO}🟠 ALTO    {RESET}",
    "MEDIO":   f"{AZUL}🟡 MEDIO   {RESET}",
    "BIEN":    f"{VERDE}🟢 BIEN    {RESET}",
    "INFO":    f"{GRIS}ℹ️  INFO    {RESET}",
}

PUNTOS_MAX = 0
PUNTOS_OBTENIDOS = 0


# ── Checks ────────────────────────────────────────────────────────────────────

def check_actualizaciones():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 15
    print(f"  {GRIS}Comprobando actualizaciones...{RESET}", end="\r")

    pendientes = cmd("apt list --upgradable 2>/dev/null | grep -c upgradable")
    try:
        n = int(pendientes) - 1  # restar la línea de cabecera
    except ValueError:
        n = 0

    if n == 0:
        PUNTOS_OBTENIDOS += 15
        check("BIEN", "Sistema actualizado",
              "No hay paquetes pendientes de actualizar.",
              "Mantén el sistema actualizado regularmente con: sudo apt update && sudo apt upgrade",
              15)
    elif n < 10:
        PUNTOS_OBTENIDOS += 8
        check("MEDIO", f"Actualizaciones pendientes ({n})",
              f"Hay {n} paquetes pendientes de actualizar.",
              "Ejecuta: sudo apt update && sudo apt upgrade",
              8)
    else:
        check("ALTO", f"Muchas actualizaciones pendientes ({n})",
              f"Hay {n} paquetes sin actualizar, algunos pueden tener vulnerabilidades.",
              "Ejecuta urgentemente: sudo apt update && sudo apt upgrade",
              0)


def check_root():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 10
    print(f"  {GRIS}Comprobando cuenta root...{RESET}", end="\r")

    shadow = leer_archivo("/etc/shadow")
    root_line = next((l for l in shadow.splitlines() if l.startswith("root:")), "")

    if root_line:
        password_field = root_line.split(":")[1]
        if password_field in ("!", "*", "!!"):
            PUNTOS_OBTENIDOS += 10
            check("BIEN", "Cuenta root bloqueada",
                  "La cuenta root no tiene contraseña activa.",
                  "Correcto. Usa sudo para tareas administrativas en lugar de root directo.",
                  10)
        else:
            check("ALTO", "Cuenta root con contraseña activa",
                  "La cuenta root tiene una contraseña configurada, lo que permite login directo.",
                  "Bloquea root con: sudo passwd -l root",
                  0)
    else:
        check("INFO", "No se pudo leer /etc/shadow",
              "Ejecuta el script con sudo para analizar la cuenta root.",
              "Ejecuta con: sudo python3 examples/auditor.py",
              0)
        PUNTOS_MAX -= 10


def check_ssh():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    print(f"  {GRIS}Comprobando SSH...{RESET}", end="\r")

    sshd_config = leer_archivo("/etc/ssh/sshd_config")
    if not sshd_config:
        return

    # Root login
    PUNTOS_MAX += 10
    root_login = re.search(r"^\s*PermitRootLogin\s+(\S+)", sshd_config, re.MULTILINE)
    if root_login and root_login.group(1).lower() in ("yes", "without-password"):
        check("CRITICO", "SSH permite login como root",
              f"PermitRootLogin está configurado como: {root_login.group(1)}",
              "Cambia en /etc/ssh/sshd_config: PermitRootLogin no\nLuego: sudo systemctl restart ssh",
              0)
    else:
        PUNTOS_OBTENIDOS += 10
        check("BIEN", "SSH no permite login como root",
              "PermitRootLogin está deshabilitado.",
              "Configuración correcta.",
              10)

    # Autenticación por contraseña
    PUNTOS_MAX += 10
    pass_auth = re.search(r"^\s*PasswordAuthentication\s+(\S+)", sshd_config, re.MULTILINE)
    if pass_auth and pass_auth.group(1).lower() == "yes":
        check("MEDIO", "SSH permite autenticación por contraseña",
              "PasswordAuthentication está habilitado — vulnerable a fuerza bruta.",
              "Usa claves SSH y desactiva contraseñas:\nPasswordAuthentication no\nLuego: sudo systemctl restart ssh",
              0)
    else:
        PUNTOS_OBTENIDOS += 10
        check("BIEN", "SSH solo acepta claves (sin contraseñas)",
              "PasswordAuthentication está deshabilitado.",
              "Configuración correcta.",
              10)

    # Puerto por defecto
    PUNTOS_MAX += 5
    puerto = re.search(r"^\s*Port\s+(\d+)", sshd_config, re.MULTILINE)
    if not puerto or puerto.group(1) == "22":
        check("MEDIO", "SSH en puerto por defecto (22)",
              "El puerto 22 es el primero que escanean los atacantes.",
              "Cambia el puerto SSH a uno no estándar (ej: 2222) en /etc/ssh/sshd_config",
              0)
    else:
        PUNTOS_OBTENIDOS += 5
        check("BIEN", f"SSH en puerto no estándar ({puerto.group(1)})",
              f"SSH está corriendo en el puerto {puerto.group(1)}.",
              "Buen enfoque para reducir ruido de bots.",
              5)

    # MaxAuthTries
    PUNTOS_MAX += 5
    max_tries = re.search(r"^\s*MaxAuthTries\s+(\d+)", sshd_config, re.MULTILINE)
    if not max_tries or int(max_tries.group(1)) > 4:
        check("MEDIO", "SSH sin límite de intentos de login",
              "MaxAuthTries no está configurado o es demasiado alto.",
              "Añade en /etc/ssh/sshd_config: MaxAuthTries 3",
              0)
    else:
        PUNTOS_OBTENIDOS += 5
        check("BIEN", f"SSH limita intentos de login (MaxAuthTries {max_tries.group(1)})",
              "Los intentos de autenticación están limitados.",
              "Configuración correcta.",
              5)


def check_firewall():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 15
    print(f"  {GRIS}Comprobando firewall...{RESET}", end="\r")

    ufw_status = cmd("sudo ufw status 2>/dev/null || ufw status 2>/dev/null")

    if "Status: active" in ufw_status:
        PUNTOS_OBTENIDOS += 15
        check("BIEN", "Firewall UFW activo",
              "UFW está habilitado y protegiendo el sistema.",
              "Revisa las reglas periódicamente con: sudo ufw status verbose",
              15)
    elif "inactive" in ufw_status:
        check("CRITICO", "Firewall UFW desactivado",
              "El firewall está instalado pero deshabilitado — el sistema está expuesto.",
              "Activa el firewall: sudo ufw enable\nRegla básica SSH: sudo ufw allow ssh",
              0)
    else:
        # Comprobar iptables
        iptables = cmd("sudo iptables -L 2>/dev/null | grep -c ACCEPT")
        if iptables and int(iptables) > 0:
            PUNTOS_OBTENIDOS += 10
            check("BIEN", "Firewall con iptables activo",
                  "Se detectaron reglas de iptables activas.",
                  "Considera usar UFW como interfaz más manejable: sudo apt install ufw",
                  10)
        else:
            check("CRITICO", "Sin firewall detectado",
                  "No se detectó UFW ni iptables activos.",
                  "Instala y activa UFW: sudo apt install ufw && sudo ufw enable",
                  0)


def check_fail2ban():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 10
    print(f"  {GRIS}Comprobando Fail2ban...{RESET}", end="\r")

    activo = cmd_ok("systemctl is-active --quiet fail2ban")
    instalado = cmd_ok("which fail2ban-client")

    if activo:
        PUNTOS_OBTENIDOS += 10
        jails = cmd("sudo fail2ban-client status 2>/dev/null | grep 'Jail list' | cut -d: -f2")
        check("BIEN", "Fail2ban activo",
              f"Fail2ban está corriendo. Jails activos: {jails.strip() or 'ninguno visible'}",
              "Verifica los jails con: sudo fail2ban-client status",
              10)
    elif instalado:
        check("ALTO", "Fail2ban instalado pero inactivo",
              "Fail2ban está instalado pero no está corriendo.",
              "Actívalo: sudo systemctl enable fail2ban && sudo systemctl start fail2ban",
              0)
    else:
        check("ALTO", "Fail2ban no instalado",
              "Sin Fail2ban el sistema es vulnerable a ataques de fuerza bruta SSH.",
              "Instálalo: sudo apt install fail2ban && sudo systemctl enable fail2ban",
              0)


def check_usuarios():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 10
    print(f"  {GRIS}Comprobando usuarios...{RESET}", end="\r")

    # Usuarios con shell activa (no sistema)
    passwd = leer_archivo("/etc/passwd")
    usuarios_shell = []
    for linea in passwd.splitlines():
        partes = linea.split(":")
        if len(partes) >= 7:
            uid = int(partes[2]) if partes[2].isdigit() else 0
            shell = partes[6]
            usuario = partes[0]
            if uid >= 1000 and shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                usuarios_shell.append(usuario)

    # Usuarios con sudo
    sudoers = cmd("grep -r '^[^#]' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")

    if len(usuarios_shell) <= 2:
        PUNTOS_OBTENIDOS += 10
        check("BIEN", f"Usuarios con shell activa: {', '.join(usuarios_shell)}",
              "Número razonable de usuarios con acceso al sistema.",
              "Revisa periódicamente con: cat /etc/passwd | grep -v nologin",
              10)
    else:
        check("MEDIO", f"Varios usuarios con shell activa ({len(usuarios_shell)})",
              f"Usuarios: {', '.join(usuarios_shell)}",
              "Revisa si todos los usuarios necesitan acceso: sudo deluser usuario",
              0)


def check_permisos():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 10
    print(f"  {GRIS}Comprobando permisos críticos...{RESET}", end="\r")

    archivos_criticos = {
        "/etc/passwd": "644",
        "/etc/shadow": "640",
        "/etc/sudoers": "440",
    }

    problemas = []
    for archivo, permiso_esperado in archivos_criticos.items():
        permiso_real = cmd(f"stat -c '%a' {archivo} 2>/dev/null")
        if permiso_real and permiso_real != permiso_esperado:
            problemas.append(f"{archivo} tiene permisos {permiso_real} (esperado: {permiso_esperado})")

    if not problemas:
        PUNTOS_OBTENIDOS += 10
        check("BIEN", "Permisos de archivos críticos correctos",
              "/etc/passwd, /etc/shadow y /etc/sudoers tienen permisos adecuados.",
              "Configuración correcta.",
              10)
    else:
        for p in problemas:
            check("CRITICO", "Permisos incorrectos en archivo crítico",
                  p,
                  "Corrige los permisos con: sudo chmod <permiso_correcto> <archivo>",
                  0)


def check_docker():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    print(f"  {GRIS}Comprobando Docker...{RESET}", end="\r")

    if not cmd_ok("which docker"):
        return

    PUNTOS_MAX += 10

    # Comprobar si el usuario está en el grupo docker (equivale a root)
    grupos = cmd("groups")
    if "docker" in grupos.split():
        check("MEDIO", "Usuario en grupo docker",
              "Estar en el grupo docker equivale a tener acceso root sin sudo.",
              "Usa sudo docker en lugar de añadir tu usuario al grupo docker.",
              0)
    else:
        PUNTOS_OBTENIDOS += 5

    # Docker socket expuesto
    if os.path.exists("/var/run/docker.sock"):
        perms = cmd("stat -c '%a' /var/run/docker.sock")
        if perms == "666":
            check("CRITICO", "Docker socket expuesto públicamente",
                  "/var/run/docker.sock tiene permisos 666 — cualquier usuario puede controlarlo.",
                  "Corrige: sudo chmod 660 /var/run/docker.sock",
                  0)
        else:
            PUNTOS_OBTENIDOS += 5
            check("BIEN", "Docker socket con permisos correctos",
                  f"/var/run/docker.sock tiene permisos {perms}.",
                  "Configuración correcta.",
                  5)


def check_unattended_upgrades():
    global PUNTOS_MAX, PUNTOS_OBTENIDOS
    PUNTOS_MAX += 5
    print(f"  {GRIS}Comprobando actualizaciones automáticas...{RESET}", end="\r")

    activo = cmd_ok("systemctl is-active --quiet unattended-upgrades")
    instalado = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades")

    if activo and instalado:
        PUNTOS_OBTENIDOS += 5
        check("BIEN", "Actualizaciones automáticas activas",
              "unattended-upgrades está instalado y activo.",
              "El sistema aplica parches de seguridad automáticamente.",
              5)
    else:
        check("MEDIO", "Sin actualizaciones automáticas",
              "unattended-upgrades no está activo.",
              "Instálalo: sudo apt install unattended-upgrades\nActívalo: sudo dpkg-reconfigure unattended-upgrades",
              0)


# ── Mostrar informe ───────────────────────────────────────────────────────────
def mostrar_informe():
    orden = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BIEN": 3, "INFO": 4}
    ordenados = sorted(hallazgos, key=lambda x: orden.get(x["nivel"], 5))

    print(f"\n{'=' * 65}")
    print(f"{NEGRITA}📋 INFORME DE SEGURIDAD — BlueshieldAA{RESET}")
    print(f"{'=' * 65}\n")

    nivel_actual = None
    for h in ordenados:
        if h["nivel"] != nivel_actual:
            nivel_actual = h["nivel"]
            print()

        icono = ICONOS.get(h["nivel"], "")
        print(f"{icono} {NEGRITA}{h['titulo']}{RESET}")
        print(f"         {GRIS}{h['detalle']}{RESET}")
        if h["nivel"] not in ("BIEN", "INFO"):
            print(f"         {CYAN}→ {h['recomendacion']}{RESET}")
        print()

    # Puntuación
    porcentaje = int((PUNTOS_OBTENIDOS / PUNTOS_MAX) * 100) if PUNTOS_MAX > 0 else 0

    if porcentaje >= 80:
        color_score = VERDE
        estado = "BUENO 💪"
    elif porcentaje >= 50:
        color_score = AMARILLO
        estado = "MEJORABLE ⚠️"
    else:
        color_score = ROJO
        estado = "CRÍTICO 🚨"

    print(f"{'=' * 65}")
    print(f"{NEGRITA}🛡️  Puntuación de seguridad: {color_score}{porcentaje}/100 — {estado}{RESET}")
    print(f"    {GRIS}({PUNTOS_OBTENIDOS} de {PUNTOS_MAX} puntos posibles){RESET}")
    print(f"{'=' * 65}\n")

    criticos = sum(1 for h in hallazgos if h["nivel"] == "CRITICO")
    altos    = sum(1 for h in hallazgos if h["nivel"] == "ALTO")
    medios   = sum(1 for h in hallazgos if h["nivel"] == "MEDIO")
    bien     = sum(1 for h in hallazgos if h["nivel"] == "BIEN")

    print(f"  {ROJO}Críticos : {criticos}{RESET}")
    print(f"  {AMARILLO}Altos    : {altos}{RESET}")
    print(f"  {AZUL}Medios   : {medios}{RESET}")
    print(f"  {VERDE}Correctos: {bien}{RESET}\n")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print(f"{NEGRITA}🛡️  BlueshieldAA - Auditor de Seguridad Local{RESET}")
    print("=" * 65)
    print(f"\n{AMARILLO}⚠️  Para resultados completos ejecuta con sudo.{RESET}\n")
    print("🔍 Analizando el sistema...\n")

    checks = [
        check_actualizaciones,
        check_root,
        check_ssh,
        check_firewall,
        check_fail2ban,
        check_usuarios,
        check_permisos,
        check_docker,
        check_unattended_upgrades,
    ]

    for check_fn in checks:
        check_fn()
        # Limpiar la línea de "comprobando..."
        print(" " * 50, end="\r")

    mostrar_informe()


if __name__ == "__main__":
    main()
