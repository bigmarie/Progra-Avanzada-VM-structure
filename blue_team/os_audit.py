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
    
    # Grupos (de /etc/group)
    ok_group, group = read_file("/etc/group")
    if ok_group:
        print("\nGrupos (de /etc/group) [grupo:gid:miembros]:")
        for line in group.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 4:
                gname, _, gid, members = parts[:4]
                members = members.strip()
                print(f" - {gname}:{gid}:{members if members else '(sin miembros listados)'}")
    else:
        warn(f"/etc/group: {group}")

    # Usuarios con acceso sudo (grupo sudo o wheel) + /etc/sudoers.d
    sudo_members = []
    if ok_group:
        for line in group.splitlines():
            if line.startswith("sudo:") or line.startswith("wheel:"):
                parts = line.split(":")
                if len(parts) >= 4:
                    sudo_members = parts[3].split(",") if parts[3].strip() else []
                    sudo_group = parts[0].split(":")[0]
                    print(f"\nPosibles administradores (grupo {sudo_group}): {', '.join([m for m in sudo_members if m]) or '(vacío)'}")

    # Accesos recientes (last)
    if which("last"):
        rc, out, err = run_cmd(["last", "-n", "15"])
        print("\nAccesos recientes (last -n 15):")
        if rc == 0 and out:
            print(out)
        else:
            warn(err or "No se pudo obtener 'last'")
    else:
        warn("'last' no está disponible en el sistema.")

    # Últimos intentos de autenticación (logs típicos)
    candidates = [
        "/var/log/auth.log",
        "/var/log/secure",   
        "/var/log/messages",
    ]
    found_any = False
    for f in candidates:
        ok_log, content = read_file(f, max_bytes=80_000)
        if ok_log:
            found_any = True
            print(f"\nExtracto de {f} (filtrado: sshd/sudo):")
            lines = []
            for line in content.splitlines()[-200:]:
                low = line.lower()
                if "sshd" in low or "sudo" in low or "authentication" in low or "failed" in low:
                    lines.append(line)
            if lines:
                print("\n".join(lines[-80:]))
            else:
                info("No se encontraron líneas relevantes en el extracto.")
    if not found_any:
        warn("No se pudieron leer logs de autenticación (puede requerir sudo o la distro usa journald).")


def open_ports():
    print_section("3) Revisión de puertos abiertos (ss/netstat)")

    # Preferimos ss (más moderno)
    if which("ss"):
        rc, out, err = run_cmd(["ss", "-tulpen"])
        print("\nPuertos/escuchas (ss -tulpen):")
        if rc == 0 and out:
            print(out)
            # Mini-análisis: detectar 0.0.0.0 / :: escuchando
            risky = []
            for line in out.splitlines():
                if "LISTEN" in line and ("0.0.0.0:" in line or "[::]:" in line):
                    risky.append(line)
            if risky:
                warn("Servicios escuchando en todas las interfaces (0.0.0.0 / ::). Revisá si es necesario exponerlos:")
                for r in risky[:15]:
                    print(f"  - {r}")
        else:
            warn(err or "No se pudo ejecutar ss")
    else:
        warn("'ss' no está disponible.")

def running_services():
    print_section("4) Servicios en ejecución (systemctl/ps)")

    # systemctl (si hay systemd)
    if which("systemctl"):
        rc, out, err = run_cmd(["systemctl", "is-system-running"])
        if rc == 0 and out:
            info(f"systemd estado: {out}")
        else:
            warn(err or "No se pudo determinar estado systemd (¿contenedor/toolbox?)")

        rc, out, err = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
        print("\nServicios activos (systemctl list-units --type=service --state=running):")
        if rc == 0 and out:
            print(out)
        else:
            warn(err or "No se pudo listar servicios con systemctl")
    else:
        warn("'systemctl' no está disponible (posible VM sin systemd, contenedor o entorno mínimo).")

    # ps como fallback universal
    if which("ps"):
        rc, out, err = run_cmd(["ps", "aux", "--sort=-%cpu"])
        print("\nProcesos (top por CPU - ps aux --sort=-%cpu) [primeras 25 líneas]:")
        if rc == 0 and out:
            lines = out.splitlines()
            print("\n".join(lines[:25]))
        else:
            warn(err or "No se pudo ejecutar ps")

        rc, out, err = run_cmd(["ps", "aux", "--sort=-%mem"])
        print("\nProcesos (top por MEM - ps aux --sort=-%mem) [primeras 25 líneas]:")
        if rc == 0 and out:
            lines = out.splitlines()
            print("\n".join(lines[:25]))
        else:
            warn(err or "No se pudo ejecutar ps (mem)")
    else:
        warn("'ps' no está disponible.")

def quick_findings():
    """
    Hallazgos rápidos (no exhaustivo) para dar señales comunes.
    """
    print_section("5) Hallazgos rápidos (checks básicos)")

    # 1) Archivos world-writable en /etc (puede ser pesado, así que acotamos)
    if which("find"):
        rc, out, err = run_cmd(["bash", "-lc", "find /etc -maxdepth 2 -type f -perm -0002 2>/dev/null | head -n 50"])
        print("\nArchivos world-writable en /etc (máx 50):")
        if rc == 0 and out:
            warn("Encontré archivos world-writable en /etc. Esto casi nunca es normal:")
            print(out)
        else:
            print("(no se encontraron o no hay permisos)")
    else:
        info("'find' no está disponible.")

    # 2) Permisos de /etc/shadow
    p = Path("/etc/shadow")
    if p.exists():
        try:
            st = p.stat()
            # Permisos en octal
            perms = oct(st.st_mode & 0o777)
            print(f"\nPermisos /etc/shadow: {perms}")
            if (st.st_mode & 0o077) != 0:
                warn("/etc/shadow tiene permisos más abiertos de lo esperado. Normalmente debería ser 640 o más restrictivo.")
        except PermissionError:
            warn("No pude stat /etc/shadow (probá con sudo).")

    # 3) Usuarios con shell interactivo (uid >= 1000 aprox) sin contraseña expirada, etc. (limitado)
    ok_passwd, passwd = read_file("/etc/passwd")
    if ok_passwd:
        interactive = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                user, _, uid, _, _, _, shell = parts[:7]
                try:
                    uid_i = int(uid)
                except ValueError:
                    continue
                if uid_i >= 1000 and shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                    interactive.append((user, uid_i, shell))
        print("\nUsuarios con shell interactivo (uid>=1000):")
        if interactive:
            for u, uid_i, sh in interactive[:80]:
                print(f" - {u} (uid={uid_i}) shell={sh}")
        else:
            print(" (ninguno)")

    # 4) UFW/firewalld/iptables (estado rápido)
    print("\nFirewall (chequeo rápido):")
    if which("ufw"):
        rc, out, _ = run_cmd(["ufw", "status"])
        print(" - ufw status:")
        print(out if out else "(sin salida)")
    if which("firewall-cmd"):
        rc, out, err = run_cmd(["firewall-cmd", "--state"])
        print(f" - firewalld: {out if rc == 0 else (err or 'desconocido')}")
    if which("iptables"):
        rc, out, err = run_cmd(["bash", "-lc", "iptables -S 2>/dev/null | head -n 40"])
        print(" - iptables -S (primeras 40 líneas):")
        print(out if rc == 0 and out else "(sin permisos o no hay reglas visibles)")

def main():
    system_info()
    users_groups()
    open_ports()
    running_services()
    quick_findings()

    print_section("Fin del reporte")
    if not is_root():
        warn("Sugerencia: ejecuta con sudo para un reporte mas completo (logs/archivos protegidos)")


if __name__ == "__main__":
    main()