import os
import json
import time
import socket
import struct
import base64
import urllib.request
import urllib.error

# Railway environment variables:
# GITHUB_TOKEN   = GitHub fine-grained token with Contents: Read and write
# GITHUB_REPO    = AzizjonLutfullayev/uzbservers-web
# GITHUB_BRANCH  = main
# INTERVAL       = 60

REPO = os.getenv("GITHUB_REPO", "AzizjonLutfullayev/uzbservers-web")
BRANCH = os.getenv("GITHUB_BRANCH", "main")
TOKEN = os.getenv("GITHUB_TOKEN", "")
INTERVAL = int(os.getenv("INTERVAL", "60"))
FILE_PATH = "public/servers.json"

SERVERS = [
    {"name":"CSZONE.UZ - Public #1","ip":"195.158.11.77","port":27015},
    {"name":"CSZONE.UZ - Public #2","ip":"195.158.11.77","port":27016},
    {"name":"CSZONE.UZ - Clanwar #1","ip":"195.158.11.77","port":27017},
    {"name":"CSZONE.UZ - Clanwar #2","ip":"195.158.11.77","port":27018},
    {"name":"NumberOne[UZ]-Public #1","ip":"83.69.139.164","port":27016},
    {"name":"NumberOne[UZ]-Public #2","ip":"83.69.139.164","port":27022},
    {"name":"NumberOne[UZ]-CSDM #1","ip":"83.69.139.164","port":27020},
    {"name":"NUMBERONE UZBEKISTAN","ip":"83.69.139.164","port":27015},
    {"name":"TIMCS.UZ Public #1","ip":"195.158.4.109","port":27015},
    {"name":"UZB ARENA","ip":"157.22.130.26","port":27015},
    {"name":"PROCS.UZ","ip":"195.158.4.108","port":27777},
    {"name":"ONECS.UZ Public #1","ip":"185.228.90.26","port":27002},
    {"name":"IHOST.UZ MIX","ip":"83.69.139.164","port":27014},
    {"name":"WEIT CS Public","ip":"84.54.82.234","port":27047},
    {"name":"CSLOVE.UZ [PUBLIC #1]","ip":"84.54.82.234","port":27015},
]

def recv_packet(sock, timeout=3):
    sock.settimeout(timeout)
    data, _ = sock.recvfrom(65535)
    return data

def parse_source(data):
    # Source A2S_INFO: FF FF FF FF 49 ...
    if len(data) < 6 or data[4] != 0x49:
        return None
    p = 5
    protocol = data[p]; p += 1

    def cstr():
        nonlocal p
        e = data.find(b"\x00", p)
        if e < 0: raise ValueError("bad string")
        s = data[p:e].decode("utf-8", "replace"); p = e + 1
        return s

    name = cstr()
    map_name = cstr()
    folder = cstr()
    game = cstr()
    if p + 2 > len(data): return None
    appid = struct.unpack_from("<H", data, p)[0]; p += 2
    if p + 2 > len(data): return None
    players = data[p]; max_players = data[p+1]; p += 2
    if p + 1 > len(data): return None
    bots = data[p]; p += 1
    return {
        "name": name, "map": map_name, "players": int(players),
        "max_players": int(max_players), "bots": int(bots),
        "online": True
    }

def parse_goldsrc(data):
    # GoldSrc A2S_INFO (0x6D)
    if len(data) < 6 or data[4] != 0x6D:
        return None
    p = 5

    def cstr():
        nonlocal p
        e = data.find(b"\x00", p)
        if e < 0: raise ValueError("bad string")
        s = data[p:e].decode("utf-8", "replace"); p = e + 1
        return s

    address = cstr()
    name = cstr()
    map_name = cstr()
    folder = cstr()
    game = cstr()
    if p + 1 > len(data): return None
    players = data[p]; p += 1
    if p + 1 > len(data): return None
    max_players = data[p]; p += 1
    return {
        "name": name, "map": map_name, "players": int(players),
        "max_players": int(max_players), "bots": 0, "online": True
    }

def query_server(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    start = time.perf_counter()
    try:
        sock.sendto(b"\xff\xff\xff\xff\x54Source Engine Query\x00", (ip, port))
        data = recv_packet(sock, 3)
        ping = round((time.perf_counter() - start) * 1000)

        info = parse_source(data) or parse_goldsrc(data)
        if info:
            info["ping"] = ping
            return info

        # Some GoldSrc servers need a challenge packet first.
        if len(data) >= 5 and data[4] == 0x41:
            challenge = data[5:9]
            sock.sendto(b"\xff\xff\xff\xff\x54Source Engine Query\x00" + challenge, (ip, port))
            data2 = recv_packet(sock, 3)
            ping = round((time.perf_counter() - start) * 1000)
            info = parse_source(data2) or parse_goldsrc(data2)
            if info:
                info["ping"] = ping
                return info

        return {"online": False, "players": 0, "max_players": 0, "map": "", "ping": None}
    except Exception:
        return {"online": False, "players": 0, "max_players": 0, "map": "", "ping": None}
    finally:
        sock.close()

def github_get_file():
    url = f"https://api.github.com/repos/{REPO}/contents/{FILE_PATH}?ref={BRANCH}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "uzbservers-monitor"
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def github_put_file(content, sha):
    raw = json.dumps(content, ensure_ascii=False, indent=2).encode()
    encoded = base64.b64encode(raw).decode()
    url = f"https://api.github.com/repos/{REPO}/contents/{FILE_PATH}"
    body = json.dumps({
        "message": "Update CS 1.6 server status",
        "content": encoded,
        "sha": sha,
        "branch": BRANCH
    }).encode()
    req = urllib.request.Request(url, data=body, method="PUT", headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "uzbservers-monitor"
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status

def build_json():
    checked_at = int(time.time())
    out = []
    for s in SERVERS:
        result = query_server(s["ip"], s["port"])
        row = {
            "name": s["name"],
            "ip": s["ip"],
            "port": s["port"],
            "online": bool(result.get("online")),
            "players": int(result.get("players", 0) or 0),
            "max_players": int(result.get("max_players", 0) or 0),
            "map": result.get("map", "") or "",
            "ping": result.get("ping"),
            "updated_at": checked_at
        }
        out.append(row)
        print(f'{s["name"]}: {"ONLINE" if row["online"] else "OFFLINE"} | {row["players"]}/{row["max_players"]} | {row["map"]} | {row["ping"]} ms')
    return {"updatedAt": checked_at, "servers": out}

def main():
    if not TOKEN:
        raise SystemExit("GITHUB_TOKEN is not set.")
    print(f"Starting monitor: every {INTERVAL}s")
    print(f"Repository: {REPO}, branch: {BRANCH}")

    while True:
        started = time.time()
        try:
            data = build_json()
            meta = github_get_file()
            status = github_put_file(data, meta["sha"])
            print(f"GitHub updated: HTTP {status}")
        except Exception as e:
            print("Update error:", repr(e))

        elapsed = time.time() - started
        sleep_for = max(5, INTERVAL - elapsed)
        print(f"Next check in {sleep_for:.1f}s")
        time.sleep(sleep_for)

if __name__ == "__main__":
    main()
