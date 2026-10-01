import json
import socket
import struct
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "servers.seed.json"
OUT = ROOT / "public" / "servers.json"

TIMEOUT = 2.0

def cstr(data, pos):
    end = data.find(b"\x00", pos)
    if end < 0:
        raise ValueError("unterminated string")
    return data[pos:end].decode("utf-8", "replace"), end + 1

def query(sock, addr, payload):
    sock.sendto(payload, addr)
    data, _ = sock.recvfrom(8192)
    # Some servers can answer with a split/multi-packet header.
    if data[:4] == b"\xff\xff\xff\xff":
        return data
    return b""

def get_info(addr):
    payload = b"\xff\xff\xff\xff\x54Source Engine Query\x00"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        started = time.monotonic()
        data = query(s, addr, payload)
        ping = round((time.monotonic() - started) * 1000)
    if len(data) < 6 or data[4:5] != b"I":
        raise ValueError("invalid A2S_INFO response")
    p = 6
    name, p = cstr(data, p)
    map_name, p = cstr(data, p)
    folder, p = cstr(data, p)
    game, p = cstr(data, p)
    if p + 10 > len(data):
        raise ValueError("short A2S_INFO response")
    app_id = struct.unpack_from("<H", data, p)[0]; p += 2
    players = data[p]; p += 1
    max_players = data[p]; p += 1
    bots = data[p]; p += 1
    dedicated = data[p]; p += 1
    os_byte = data[p:p+1]; p += 1
    password = data[p]; p += 1
    vac = data[p]; p += 1
    version, p = cstr(data, p)
    return {
        "name": name,
        "map": map_name,
        "folder": folder,
        "game": game,
        "players": players,
        "maxPlayers": max_players,
        "bots": bots,
        "ping": ping,
        "vac": bool(vac),
        "password": bool(password),
        "version": version,
    }

def get_players(addr):
    challenge_request = b"\xff\xff\xff\xff\x55\xff\xff\xff\xff"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.sendto(challenge_request, addr)
        data, _ = s.recvfrom(8192)
        if len(data) < 9:
            raise ValueError("no A2S_PLAYER challenge")
        if data[:4] != b"\xff\xff\xff\xff":
            raise ValueError("bad A2S_PLAYER challenge")
        if data[4:5] == b"A":
            challenge = data[5:9]
        elif data[4:5] == b"D":
            # Some implementations accept -1 directly and return players.
            return parse_players(data)
        else:
            raise ValueError("unexpected A2S_PLAYER challenge response")
        s.sendto(b"\xff\xff\xff\xff\x55" + challenge, addr)
        reply, _ = s.recvfrom(8192)
    return parse_players(reply)

def parse_players(data):
    if len(data) < 6 or data[:4] != b"\xff\xff\xff\xff" or data[4:5] != b"D":
        raise ValueError("invalid A2S_PLAYER response")
    count = data[5]
    p = 6
    players = []
    for _ in range(count):
        if p >= len(data):
            break
        index = data[p]; p += 1
        name, p = cstr(data, p)
        if p + 8 > len(data):
            break
        score = struct.unpack_from("<i", data, p)[0]; p += 4
        duration = struct.unpack_from("<f", data, p)[0]; p += 4
        players.append({
            "index": index,
            "name": name,
            "score": score,
            "duration": round(max(0.0, duration), 1)
        })
    return players

def main():
    seeds = json.loads(SEED.read_text(encoding="utf-8"))
    results = []
    for item in seeds:
        host, port = item["ip"].rsplit(":", 1)
        addr = (host, int(port))
        row = {
            "name": item["name"],
            "ip": item["ip"],
            "online": False,
            "players": 0,
            "maxPlayers": 0,
            "map": "—",
            "ping": None,
            "playerList": [],
            "updatedAt": int(time.time())
        }
        try:
            info = get_info(addr)
            row.update({
                "online": True,
                "players": info["players"],
                "maxPlayers": info["maxPlayers"],
                "map": info["map"],
                "ping": info["ping"],
            })
            try:
                row["playerList"] = get_players(addr)
            except Exception:
                row["playerList"] = []
        except Exception as e:
            row["error"] = str(e)[:120]
        results.append(row)
        print(item["ip"], "ONLINE" if row["online"] else "OFFLINE",
              row["players"], "/", row["maxPlayers"])
    OUT.write_text(
        json.dumps({"updatedAt": int(time.time()), "servers": results},
                   ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

if __name__ == "__main__":
    main()
