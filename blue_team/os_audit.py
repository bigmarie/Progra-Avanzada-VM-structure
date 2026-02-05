import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path

# HELPERS

def run_cmd(cmd, timeout=12):
    """
    Esta funcion ejecuta un comando y devuelve (rc, stdout, stderr).
    cmd: lista (recomendado) o string.
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", f"Comando no encontrado: {cmd[0] if isinstance(cmd, list) else cmd}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout ejecutado: {cmd}"
    except Exception as e:
        return 1, "", f"Error ejecutando {cmd}:{e}"

def which(binary):
    """ Esta funcion devuelve True si el binario existe en PATH."""
    rc, _, _ = run_cmd(["bash", "-lc", f"command -v {binary} >/dev/null 2>&1"])
    return rc == 0

def read_file(path, max_bytes=200_000):
    """
    Esta funcion lee un archivo de texto con limite.
    Devuelve ok, contenido o error.
    """
    try:
        p = Path(path)
        if not p.exists():
            return False, "NO EXISTE"
        if not p.is_file():
            return False, "NO ES ARCHIVO"
        data = p.read_bytes()
        if len(data) > max_bytes:
            data = data[:max_bytes] + b"\n\n[...TRUNCANDO...]\n"
        # intento de decode seguro
        text = data.decode("utf-8", errors="replace")
        return True, text.strip()
    except PermissionError:
        return False, "PERMISO DENEGADO"
    except Exception as e:
        return False, f"ERROR: {e}"

def print_section(title):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

def warn(msg):
    print(f"[!] {msg}")

def ok(msg):
    print(f"[+] {msg}")

def info(msg):
    print(f"[*] {msg}")

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# AUDITORIA
def system_info():
    print_section("1) Informacion del sistema")
    info(f"Fecha/hora: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    info(f"Hostname: {platform.node()}")
    info(f"SO: {platform.system()} {platform.release()} ({platform.version()})")
    info(f"Arquitectura: {platform.machine()}")
    info(f"Python: {platform.python_version()}")
    info(f"Usuario actual: {os.getenv('USER', 'N/A')}")
    info(f"UID/EUID root: {'SI' if is_root() else 'NO'}")

    # distribucion (si existe /etc/os-release)
    ok_osr, osr = read_file("/etc/os-release")
    if ok_osr:
        print("\n/etc/os-release:")
        print(osr)
    else:
        warn(f"/etc/os-release: {osr}")

def users_groups():
    print_section("2) Usuarios, grupos y accesos recientes")

    # usuarios (de /etc/passwd)
    ok_passwd, passwd = read_file("/etc/passwd")
    if ok_passwd:
        print("\nUsuarios (de /etc/passwd) [usuario:uid:gid:shell]:")
        lines = []
        for line in passwd.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                user, _, uid, gid, _, _, shell = parts[:7]
                lines.append((user, uid, gid, shell))
        
        # orden por uid numerico
        def uid_key(t):
            try:
                return int(t[1])
            except ValueError:
                return 999999
        
        for user,uid,gid,shell in sorted(lines, key=uid_key):
            print(f" - {user}:{uid}:{gid}:{shell}")
        
        # checks simples
        root_shells = [t for t in lines if t[0] == "root"]
        if root_shells and root_shells[0][3] not in ("/bin/bash", "/bin/sh", "usr/bin/bash", "/usr/bin/sh"):
            warn(f"Shell de root inusual: {root_shells[0][3]}")
    else:
        warn(f"/etc/passwd: {passwd}")

def main():
    system_info()
    users_groups()
    
    print_section("Fin del reporte")
    if not is_root():
        warn("Sugerencia: ejecuta con sudo para un reporte mas completo (logs/archivos protegidos)")


if __name__ == "__main__":
    main()