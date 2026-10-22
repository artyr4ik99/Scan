"""
netid.py - определение узлов сети: производитель по MAC (OUI), догадка ОС по
TTL, NetBIOS-имя, HTTP/баннер-информация, SNMP sysDescr, SSDP/UPnP-поиск и
итоговая классификация типа устройства (камера, роутер, NAS, принтер, ПК...).

Общий модуль для netscan.py (консольный сканер) и netsuite.py (GUI: просмотр
камер + сканер сети). Используется ТОЛЬКО для диагностики своей сети или
сети, на проверку которой у вас есть разрешение.
"""
import http.client
import os
import platform
import re
import socket
import subprocess
import time

IS_WIN = platform.system() == "Windows"
_POPEN_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}

# ----------------------------------------------------------------------
# OUI (первые 3 байта MAC) -> производитель. Компактный, но практичный
# список самых распространённых производителей IP-камер/NVR, сетевого
# оборудования, NAS, ПК и IoT-устройств. Не official IEEE-реестр, но
# покрывает большинство узлов типичной сети.
# ----------------------------------------------------------------------
OUI_VENDORS = {
    # IP-камеры / NVR
    "001349": "Tiandy", "8CE284": "Tiandy", "446D57": "Tiandy",
    "0C8C24": "Hikvision", "4C1110": "Hikvision", "C04A00": "Hikvision",
    "A4147B": "Hikvision", "BCADAB": "Hikvision", "2C5BB8": "Hikvision",
    "001C63": "Dahua", "90026D": "Dahua", "3C8C40": "Dahua", "E04FBD": "Dahua",
    "001A64": "Uniview", "2CAB00": "Uniview",
    "00408C": "Axis", "ACCC8E": "Axis", "00400F": "Axis",
    "0019CB": "Vivotek", "0002D1": "Vivotek",
    "B075D5": "Reolink", "EC71DB": "Reolink",
    "001438": "Foscam", "E89FD0": "Foscam",
    "7CDD90": "Hanwha/Samsung", "0016B6": "Hanwha/Samsung",
    "000D56": "Bosch Security",
    # Сетевое оборудование
    "001FCA": "Huawei", "00E0FC": "Huawei", "28313C": "Huawei",
    "0019E0": "D-Link", "001195": "D-Link", "14D64D": "D-Link",
    "0024A5": "TP-Link", "503EAA": "TP-Link", "C46E1F": "TP-Link",
    "F4F26D": "TP-Link", "001E58": "TP-Link",
    "0022F7": "Cisco", "001A2F": "Cisco", "00D0BC": "Cisco",
    "0007EC": "Cisco", "001CF9": "Cisco",
    "00904C": "Zyxel", "0013D4": "Zyxel",
    "00156D": "Ubiquiti", "0418D6": "Ubiquiti", "24A43C": "Ubiquiti",
    "FCECDA": "Ubiquiti", "DC9FDB": "Ubiquiti", "687251": "Ubiquiti",
    "B4FBE4": "Keenetic", "D4CA6D": "Keenetic",
    "001D0F": "MikroTik", "4C5E0C": "MikroTik", "6C3B6B": "MikroTik", "E48D8C": "MikroTik",
    "001060": "Fortinet", "0009A8": "Juniper",
    "001217": "Netgear", "20E52A": "Netgear", "E09467": "Netgear",
    "C83A35": "ASUSTek", "F832E4": "ASUSTek", "1C872C": "ASUSTek", "2C56DC": "ASUSTek",
    # NAS / сервера
    "001132": "Synology", "24A0D7": "Synology", "001E8E": "QNAP", "245E8E": "QNAP",
    # ПК / ноутбуки / рабочие станции
    "3417EB": "Dell", "D4BED9": "Dell", "A4BADB": "Dell",
    "A45E60": "Apple", "F0DBE2": "Apple", "88E9FE": "Apple", "DC2B2A": "Apple",
    "3C0754": "Apple", "A8667F": "Apple", "F41BA1": "Apple",
    "3CA067": "Intel", "001320": "Intel",
    "001A11": "Google", "F4F5D8": "Google", "3C5AB4": "Google",
    "001E65": "Lenovo", "9C2A70": "Lenovo", "D4C9EF": "Lenovo",
    "0024D7": "Hewlett Packard", "9C8E99": "HP",
    # Мобильные / IoT
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "D83ADD": "Samsung", "8871E5": "Samsung", "001377": "Samsung",
    "FCA621": "Espressif (IoT, ESP8266/32)", "246F28": "Espressif", "A020A6": "Espressif",
    "B0B21C": "Sonos", "5CAAFD": "Amazon (Echo/Fire)", "68DBCA": "Amazon",
}

CAMERA_HINTS = ("tiandy", "hikvision", "hik-", "dahua", "dh-ipc", "uniview", "reolink",
                "foscam", "vivotek", "axis", "wisenet", "hanwha", "ipc-", "nvr", "dvr", "onvif")
PRINTER_HINTS = ("printer", "lexmark", "epson", "canon", "brother", "jetdirect")
NAS_HINTS = ("synology", "qnap", "nas", "truenas", "diskstation")
ROUTER_HINTS = ("router", "mikrotik", "routeros", "keenetic", "ubiquiti", "openwrt",
                "cisco", "huawei", "zte", "gpon", "ont ", "switch", "коммутатор")


def mac_vendor(mac):
    """Производитель по OUI (первые 3 байта MAC-адреса)."""
    if not mac:
        return ""
    key = re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper()
    return OUI_VENDORS.get(key, "")


def local_ip():
    """IP основного интерфейса этого компьютера (без реальной отправки
    пакетов — просто просит ОС выбрать маршрут)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def default_gateway():
    """IP шлюза по умолчанию (для построения локальной топологии)."""
    try:
        if IS_WIN:
            r = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                timeout=5, **_POPEN_FLAGS)
            m = re.search(r"(?:Default Gateway|Основной шлюз)[^\d]*(\d+\.\d+\.\d+\.\d+)", r.stdout)
            return m.group(1) if m else ""
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""


def read_arp_table():
    """ip -> mac из системной ARP-таблицы (видно только в своём L2-сегменте,
    то есть без промежуточного маршрутизатора)."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                              timeout=5, **_POPEN_FLAGS).stdout
    except Exception:
        return {}
    table = {}
    rx = re.compile(r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
    for ip, mac in rx.findall(out):
        parts = re.split(r"[:-]", mac)
        table[ip] = ":".join(p.zfill(2) for p in parts).lower()
    return table


def ping_ttl(ip, timeout_ms=1000):
    """TTL из ответа ping (грубая эвристика ОС): ~64 - Linux/Unix/сетевое
    устройство, ~128 - Windows, ~255 - маршрутизатор/коммутатор. Возвращает
    None, если узел не отвечает на ICMP (бывает при файрволе)."""
    try:
        if IS_WIN:
            r = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), ip],
                                capture_output=True, text=True, timeout=5, **_POPEN_FLAGS)
            m = re.search(r"TTL=(\d+)", r.stdout, re.I)
        else:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                capture_output=True, text=True, timeout=5)
            m = re.search(r"ttl=(\d+)", r.stdout, re.I)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def guess_os_by_ttl(ttl):
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/Unix/встроенное устройство (TTL≈64)"
    if ttl <= 128:
        return "Windows (TTL≈128)"
    return "Сетевое оборудование (TTL≈255)"


def tcp_banner(ip, port, timeout=1.2):
    """Первые байты ответа сервиса (SSH/FTP/SMTP и т.п. присылают баннер сами,
    сразу после установления соединения)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            return data.decode(errors="ignore").strip()
    except OSError:
        return ""


def http_info(ip, port, timeout=2.0):
    """Заголовок Server, <title> страницы и наличие HTTP-авторизации."""
    try:
        c = http.client.HTTPConnection(ip, port, timeout=timeout)
        c.request("GET", "/", headers={"User-Agent": "netid-scan"})
        r = c.getresponse()
        server = r.getheader("Server") or ""
        www_auth = r.getheader("WWW-Authenticate") or ""
        body = r.read(4096).decode(errors="ignore")
        c.close()
        m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
        return {"server": server, "title": title, "auth": www_auth, "status": r.status}
    except Exception:
        return {}


def netbios_name(ip, timeout=1.5):
    """NBSTAT-запрос (UDP 137) для NetBIOS-имени узла (Windows/Samba).
    Best-effort: при любой ошибке возвращает ''."""
    try:
        tid = os.urandom(2)
        header = tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        name = b"*" + b"\x00" * 15
        encoded = bytearray()
        for b in name:
            encoded.append(0x41 + ((b >> 4) & 0xF))
            encoded.append(0x41 + (b & 0xF))
        question = b"\x20" + bytes(encoded) + b"\x00" + b"\x00\x21\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + question, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) < 57:
            return ""
        num_names = data[56]
        pos = 57
        for _ in range(num_names):
            raw = data[pos:pos + 15]
            pos += 18
            nm = raw.decode(errors="ignore").strip()
            if nm:
                return nm
        return ""
    except Exception:
        return ""


# ---- минимальный SNMP v1 GET (без внешних зависимостей, только sysDescr) ----

def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _ber_tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _encode_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 128:
            body.append(p)
        else:
            chunk = [p & 0x7F]
            p >>= 7
            while p:
                chunk.insert(0, (p & 0x7F) | 0x80)
                p >>= 7
            body.extend(chunk)
    return bytes(body)


def _read_tlv(data, pos):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    value = data[pos:pos + length]
    return tag, value, pos + length


def snmp_get(ip, oid="1.3.6.1.2.1.1.1.0", community="public", timeout=1.2, port=161):
    """Минимальный SNMPv1 GET. По умолчанию запрашивает sysDescr (обычно
    содержит модель/прошивку устройства). Возвращает строку или ''."""
    try:
        req_id = int.from_bytes(os.urandom(2), "big")
        version = _ber_tlv(0x02, b"\x00")
        comm = _ber_tlv(0x04, community.encode())
        oid_enc = _ber_tlv(0x06, _encode_oid(oid))
        null_enc = _ber_tlv(0x05, b"")
        varbind = _ber_tlv(0x30, oid_enc + null_enc)
        varbindlist = _ber_tlv(0x30, varbind)
        rid = _ber_tlv(0x02, req_id.to_bytes(2, "big"))
        err = _ber_tlv(0x02, b"\x00")
        erridx = _ber_tlv(0x02, b"\x00")
        pdu = _ber_tlv(0xA0, rid + err + erridx + varbindlist)
        packet = _ber_tlv(0x30, version + comm + pdu)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (ip, port))
        data, _ = s.recvfrom(4096)
        s.close()

        _, seq, _ = _read_tlv(data, 0)
        pos = 0
        _, _, pos = _read_tlv(seq, pos)          # version
        _, _, pos = _read_tlv(seq, pos)          # community
        _, pdu_val, _ = _read_tlv(seq, pos)       # GetResponse-PDU
        p2 = 0
        _, _, p2 = _read_tlv(pdu_val, p2)         # request-id
        _, _, p2 = _read_tlv(pdu_val, p2)         # error-status
        _, _, p2 = _read_tlv(pdu_val, p2)         # error-index
        _, vbl, _ = _read_tlv(pdu_val, p2)        # varbind list
        _, vb, _ = _read_tlv(vbl, 0)              # первый varbind
        p3 = 0
        _, _, p3 = _read_tlv(vb, 0)               # OID
        tag, val, _ = _read_tlv(vb, p3)
        return val.decode(errors="ignore").strip() if tag == 0x04 else ""
    except Exception:
        return ""


def ssdp_discover(timeout=2.5):
    """UPnP/SSDP M-SEARCH: роутеры, NAS, медиасерверы, умные устройства и
    т.п., отвечающие на стандартный широковещательный discovery-запрос."""
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           "HOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\n"
           "ST: ssdp:all\r\n\r\n").encode()
    found = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode(errors="ignore")
            server = re.search(r"SERVER:\s*(.+)", text, re.I)
            loc = re.search(r"LOCATION:\s*(.+)", text, re.I)
            d = found.setdefault(ip, {"server": "", "location": ""})
            if server:
                d["server"] = server.group(1).strip()
            if loc:
                d["location"] = loc.group(1).strip()
        s.close()
    except Exception:
        pass
    return found


def classify_device(vendor, ports, banner_text, os_guess, hostname):
    """Грубая эвристика типа устройства по производителю, открытым портам,
    баннерам и догадке ОС. Не точная детекция, а подсказка для оператора."""
    text = " ".join(filter(None, [vendor, banner_text, hostname])).lower()
    ports = set(ports or [])

    def has(hints):
        return any(h in text for h in hints)

    if has(CAMERA_HINTS) or 554 in ports or 8554 in ports:
        return "IP-камера/NVR"
    if has(PRINTER_HINTS) or 9100 in ports or 631 in ports:
        return "Принтер"
    if has(NAS_HINTS) or 548 in ports or (445 in ports and 5000 in ports):
        return "NAS/файловый сервер"
    if has(ROUTER_HINTS) or (53 in ports and (80 in ports or 443 in ports) and 22 not in ports):
        return "Роутер/коммутатор/шлюз"
    if 3389 in ports or "windows" in os_guess.lower():
        return "Windows ПК/сервер"
    if 22 in ports and "linux" in os_guess.lower():
        return "Linux-сервер/устройство"
    if 5900 in ports:
        return "Устройство с VNC"
    if 1883 in ports or 8883 in ports:
        return "IoT (MQTT)"
    if vendor and any(v in vendor for v in ("Espressif", "Sonos", "Amazon", "Raspberry")):
        return "IoT/умное устройство"
    if 80 in ports or 443 in ports:
        return "Устройство с веб-интерфейсом"
    if ports:
        return "Неизвестное сетевое устройство"
    return "Неизвестно"


def identify_host(ip, ports=None, mac=None, timeout=1.2, do_snmp=True):
    """Собирает всё, что можно узнать об узле без аутентификации: MAC и
    производитель, догадка ОС по TTL, имя (DNS/NetBIOS), HTTP-баннер, SNMP
    sysDescr, итоговый тип устройства. Используйте только для своей сети."""
    ports = ports or []
    if mac is None:
        mac = read_arp_table().get(ip, "")
    vendor = mac_vendor(mac)
    ttl = ping_ttl(ip, int(timeout * 1000))
    os_guess = guess_os_by_ttl(ttl)
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass
    nb = netbios_name(ip, timeout) if (139 in ports or 445 in ports) else ""
    web = next((p for p in (80, 8080, 8000, 8081, 88) if p in ports), None)
    http_d = http_info(ip, web, timeout) if web else {}
    banner_parts = [http_d.get("server", ""), http_d.get("title", "")]
    for p in (21, 22, 23, 25):
        if p in ports:
            b = tcp_banner(ip, p, min(timeout, 1.0))
            if b:
                banner_parts.append(b)
            break
    sysdescr = snmp_get(ip, timeout=min(timeout, 1.0)) if (do_snmp and 161 in ports) else ""
    if sysdescr:
        banner_parts.append(sysdescr)
    banner_text = " | ".join(x for x in banner_parts if x)
    device_type = classify_device(vendor, ports, banner_text, os_guess, hostname or nb)
    return {
        "ip": ip, "mac": mac, "vendor": vendor, "os_guess": os_guess,
        "hostname": hostname, "netbios": nb, "http": http_d, "sysdescr": sysdescr,
        "banner": banner_text, "device_type": device_type,
    }
