#!/usr/bin/env python3
"""
netscan.py - консольный сканер своей сети: находит узлы, определяет, что это
за устройство (производитель, ОС, тип), и позволяет подключиться к найденному
узлу (SSH/Telnet/веб/RDP/raw TCP).

Используется ТОЛЬКО для диагностики собственной сети или сети, на проверку
которой у вас есть разрешение.

Использование:
    python netscan.py                      # автоопределение подсети (/24)
    python netscan.py 192.168.1.0/24
    python netscan.py 10.0.0.0/24 10.0.1.0/24 --timeout 0.5
    python netscan.py 192.168.1.0/24 --json out.json
    python netscan.py 192.168.1.0/24 --csv out.csv --no-identify
"""
import argparse
import csv
import ipaddress
import json
import platform
import shutil
import socket
import subprocess
import webbrowser
from concurrent.futures import ThreadPoolExecutor

import netid
import topology

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 161: "snmp", 443: "https",
    445: "smb", 548: "afp", 554: "rtsp", 631: "ipp", 1883: "mqtt",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 8554: "rtsp-alt",
    9100: "printer",
}
QUICK_PORTS = (22, 80, 443, 445, 3389)  # для быстрой проверки "живой/нет"
IS_WIN = platform.system() == "Windows"


# ---------- обнаружение ----------

def detect_local_network() -> str:
    """IP основного интерфейса (пакеты не отправляются), берёт /24."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def ping(ip: str) -> bool:
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    elif platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def probe(ip: str, timeout: float) -> dict:
    alive = ping(ip) or any(tcp_open(ip, p, timeout) for p in QUICK_PORTS)
    if not alive:
        return {"ip": ip, "alive": False}
    ports = [p for p in COMMON_PORTS if tcp_open(ip, p, timeout)]
    return {"ip": ip, "alive": True, "ports": ports, "name": resolve_name(ip)}


def scan(networks: list, timeout: float, workers: int) -> list:
    targets = []
    for n in networks:
        targets += [str(h) for h in ipaddress.ip_network(n, strict=False).hosts()]

    print(f"Сканирую {len(targets)} адресов...")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = {r["ip"]: r for r in ex.map(lambda ip: probe(ip, timeout), targets)}

    # Узлы, блокирующие ping и наши порты, всё равно попадают в ARP
    arp = netid.read_arp_table()
    target_set = set(targets)
    for ip, mac in arp.items():
        if ip in target_set and not results[ip]["alive"]:
            results[ip] = {"ip": ip, "alive": True, "ports": [], "name": resolve_name(ip)}

    hosts = [r for r in results.values() if r["alive"]]
    for h in hosts:
        h["mac"] = arp.get(h["ip"], "")
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return hosts


def identify_all(hosts: list, timeout: float, workers: int) -> None:
    print("Определяю тип устройств...")

    def one(h):
        d = netid.identify_host(h["ip"], h["ports"], mac=h.get("mac"), timeout=timeout)
        h.update(d)
        return h

    with ThreadPoolExecutor(max_workers=min(workers, 32)) as ex:
        list(ex.map(one, hosts))


# ---------- вывод и подключение ----------

def print_hosts(hosts: list) -> None:
    print(f"\n{'#':>3}  {'IP':<16} {'MAC':<18} {'Производитель':<16} {'Тип устройства':<24} Порты")
    for i, h in enumerate(hosts, 1):
        ports = ",".join(f"{p}/{COMMON_PORTS.get(p, p)}" for p in h["ports"]) or "-"
        vendor = h.get("vendor", "") or "-"
        dtype = h.get("device_type", "") or "-"
        print(f"{i:>3}  {h['ip']:<16} {h.get('mac') or '-':<18} {vendor[:15]:<16} {dtype[:23]:<24} {ports}")
        name_bits = [x for x in (h.get("name"), h.get("hostname"), h.get("netbios")) if x]
        banner = h.get("banner", "")
        if name_bits or banner:
            extra = " / ".join(dict.fromkeys(name_bits))
            tail = " | ".join(x for x in (extra, banner) if x)
            print(f"     {tail}")


def raw_tcp(ip: str, port: int) -> None:
    """Минимальный netcat: вводите строки, видите ответ. Ctrl+C - выход."""
    with socket.create_connection((ip, port), timeout=3) as s:
        s.settimeout(1)
        print(f"Подключено к {ip}:{port}. Ctrl+C для выхода.")
        try:
            while True:
                try:
                    data = s.recv(4096)
                    if data:
                        print(data.decode(errors="replace"), end="")
                except socket.timeout:
                    pass
                line = input("> ")
                s.sendall((line + "\r\n").encode())
        except (KeyboardInterrupt, EOFError, OSError):
            print("\nОтключено.")


def connect(host: dict) -> None:
    ip, ports = host["ip"], host["ports"]
    actions = []  # (описание, функция)
    if 22 in ports and shutil.which("ssh"):
        actions.append(("SSH", lambda: subprocess.call(
            ["ssh", f"{input('Пользователь: ').strip()}@{ip}"])))
    if 23 in ports and shutil.which("telnet"):
        actions.append(("Telnet", lambda: subprocess.call(["telnet", ip])))
    for p, scheme in ((80, "http"), (8080, "http"), (443, "https"), (8443, "https")):
        if p in ports:
            actions.append((f"Открыть {scheme}://{ip}:{p} в браузере",
                            lambda s=scheme, p=p: webbrowser.open(f"{s}://{ip}:{p}")))
    if 3389 in ports:
        if IS_WIN:
            actions.append(("RDP (mstsc)", lambda: subprocess.call(["mstsc", f"/v:{ip}"])))
        elif shutil.which("xfreerdp"):
            actions.append(("RDP (xfreerdp)", lambda: subprocess.call(
                ["xfreerdp", f"/v:{ip}", f"/u:{input('Пользователь: ').strip()}"])))
    if 5900 in ports:
        for name in ("vncviewer", "vinagre", "remmina"):
            if shutil.which(name):
                actions.append((f"VNC ({name})", lambda n=name: subprocess.call([n, ip])))
                break
    for p in ports:
        actions.append((f"Сырое TCP-соединение к порту {p} ({COMMON_PORTS.get(p, '?')})",
                        lambda p=p: raw_tcp(ip, p)))
    actions.append(("Raw TCP на произвольный порт",
                    lambda: raw_tcp(ip, int(input("Порт: ")))))

    for i, (desc, _) in enumerate(actions, 1):
        print(f"  {i}. {desc}")
    choice = input("Действие (Enter - назад): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(actions):
        actions[int(choice) - 1][1]()


def export(hosts: list, path: str) -> None:
    rows = [{
        "ip": h["ip"], "mac": h.get("mac", ""), "vendor": h.get("vendor", ""),
        "device_type": h.get("device_type", ""), "os_guess": h.get("os_guess", ""),
        "hostname": h.get("hostname") or h.get("name", ""),
        "ports": ",".join(map(str, h.get("ports", []))), "banner": h.get("banner", ""),
    } for h in hosts]
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
    else:
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else
                                ["ip", "mac", "vendor", "device_type", "os_guess",
                                 "hostname", "ports", "banner"])
            w.writeheader()
            w.writerows(rows)
    print(f"Экспортировано в {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Сканер собственной сети с определением устройств")
    ap.add_argument("networks", nargs="*", help="CIDR-подсети, напр. 192.168.1.0/24")
    ap.add_argument("--timeout", type=float, default=0.4, help="таймаут TCP, сек")
    ap.add_argument("--workers", type=int, default=128, help="число потоков")
    ap.add_argument("--no-identify", action="store_true",
                    help="не определять производителя/тип устройства (только порты)")
    ap.add_argument("--json", metavar="FILE", help="сохранить результат в JSON")
    ap.add_argument("--csv", metavar="FILE", help="сохранить результат в CSV")
    ap.add_argument("--topology-dot", metavar="FILE",
                    help="сохранить локальную топологию (этот ПК/шлюз/узлы) в Graphviz DOT")
    ap.add_argument("--snmp-topology", metavar="IP[,IP2,...]",
                    help="построить топологию через LLDP/MAC-таблицы управляемых "
                         "коммутаторов (SNMP), начиная с этих IP")
    ap.add_argument("--snmp-community", default="public",
                    help="SNMP community для --snmp-topology (по умолчанию public)")
    ap.add_argument("--snmp-dot", metavar="FILE", help="куда сохранить DOT для --snmp-topology")
    args = ap.parse_args()

    networks = args.networks or [detect_local_network()]
    print("Подсети:", ", ".join(networks))
    hosts = scan(networks, args.timeout, args.workers)
    if not args.no_identify and hosts:
        identify_all(hosts, max(args.timeout, 1.0), args.workers)

    if args.json:
        export(hosts, args.json)
    if args.csv:
        export(hosts, args.csv)

    if args.topology_dot:
        hosts_for_topo = [dict(h, ip=h["ip"]) for h in hosts]
        topo = topology.build_local_topology(
            hosts_for_topo, my_ip=netid.local_ip(), gateway_ip=netid.default_gateway())
        with open(args.topology_dot, "w", encoding="utf-8") as f:
            f.write(topology.export_dot(topo, "local-network"))
        print(f"Локальная топология сохранена в {args.topology_dot}\n"
              f"  Просмотр: dot -Tpng {args.topology_dot} -o topo.png  (пакет graphviz)\n"
              f"  или вставьте содержимое файла на https://dreampuf.github.io/GraphvizOnline/")

    if args.snmp_topology:
        seeds = [s.strip() for s in args.snmp_topology.split(",") if s.strip()]
        print(f"Опрашиваю по SNMP: {', '.join(seeds)} (community={args.snmp_community})...")
        snmp_topo = topology.build_snmp_topology(
            seeds, community=args.snmp_community, hosts=hosts)
        print(f"SNMP-топология: {len(snmp_topo['nodes'])} узлов, {len(snmp_topo['edges'])} связей.")
        for err in snmp_topo.get("errors", []):
            print("  ", err)
        if args.snmp_dot:
            with open(args.snmp_dot, "w", encoding="utf-8") as f:
                f.write(topology.export_dot(snmp_topo, "switch-topology"))
            print(f"Сохранено в {args.snmp_dot}")
        else:
            print("  (используйте --snmp-dot FILE, чтобы сохранить DOT-файл)")

    while True:
        print_hosts(hosts)
        cmd = input("\nНомер узла для подключения, 'r' - пересканировать, 'q' - выход: ").strip()
        if cmd == "q":
            break
        if cmd == "r":
            hosts = scan(networks, args.timeout, args.workers)
            if not args.no_identify and hosts:
                identify_all(hosts, max(args.timeout, 1.0), args.workers)
        elif cmd.isdigit() and 1 <= int(cmd) <= len(hosts):
            connect(hosts[int(cmd) - 1])


if __name__ == "__main__":
    main()
