import json
import socket
import struct
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEED = ROOT / "servers.seed.json"
OUT = ROOT / "public" / "servers.json"

TIMEOUT = 3.0
A2S_INFO = b"\xff\xff\xff\xff\x54Source Engine Query\x00"


def cstr(data, pos):
    end = data.find(b"\x00", pos)
    if end < 0:
        raise ValueError("unterminated string")
    return data[pos:end].decode("utf-8", "replace"), end + 1


def recv_packet(sock):
    data, _ = sock.recvfrom(65535)

    # Normal single UDP packet.
    if data[:4] == b"\xff\xff\xff\xff":
        return data

    # Ignore unexpected packets instead of treating them as a valid response.
    return b""


def get_info(addr):
    """
    A2S_INFO with challenge support.

    Some CS 1.6 / GoldSrc servers return:
        FF FF FF FF 41 <4-byte challenge>
    first. In that case the same A2S_INFO request must be
    resent with the 4-byte challenge appended.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)

        started = time.monotonic()
        s.sendto(A2S_INFO, addr)
        data = recv_packet(s)

        if len(data) < 5:
            raise ValueError("empty A2S_INFO response")

        response_type = data[4:5]

        # Server requires an A2S_INFO challenge.
        if response_type == b"A":
            if len(data) < 9:
                raise ValueError("short A2S_INFO challenge")

            challenge = data[5:9]

            s.sendto(A2S_INFO + challenge, addr)
            data = recv_packet(s)

            if len(data) < 5:
                raise ValueError("empty A2S_INFO response after challenge")

            response_type = data[4:5]

        ping = round((time.monotonic() - started) * 1000)

    # Standard A2S_INFO response.
    if response_type != b"I":
        raise ValueError(
            f"unexpected A2S_INFO response: 0x{data[4]:02x}"
        )

    # FF FF FF FF + I + protocol
    if len(data) < 6:
        raise ValueError("short A2S_INFO response")

    protocol = data[5]
    p = 6

    name, p = cstr(data, p)
    map_name, p = cstr(data, p)
    folder, p = cstr(data, p)
    game, p = cstr(data, p)

    # appid(2) + players(1) + maxplayers(1) + bots(1)
    # + server type(1) + OS(1) + password(1) + VAC(1)
    if p + 8 > len(data):
        raise ValueError("short A2S_INFO response")

    app_id = struct.unpack_from("<H", data, p)[0]
    p += 2

    players = data[p]
    p += 1

    max_players = data[p]
    p += 1

    bots = data[p]
    p += 1

    dedicated = data[p]
    p += 1

    os_byte = data[p:p + 1]
    p += 1

    password = data[p]
    p += 1

    vac = data[p]
    p += 1

    version = ""
    if p < len(data):
        version, p = cstr(data, p)

    return {
        "protocol": protocol,
        "appId": app_id,
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
    """
    A2S_PLAYER query with challenge support.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)

        # Initial A2S_PLAYER request with -1 challenge.
        challenge_request = (
            b"\xff\xff\xff\xff"
            b"\x55"
            b"\xff\xff\xff\xff"
        )

        s.sendto(challenge_request, addr)
        data = recv_packet(s)

        if len(data) < 5:
            raise ValueError("no A2S_PLAYER response")

        response_type = data[4:5]

        if response_type == b"A":
            if len(data) < 9:
                raise ValueError("short A2S_PLAYER challenge")

            challenge = data[5:9]

            s.sendto(
                b"\xff\xff\xff\xff\x55" + challenge,
                addr
            )

            data = recv_packet(s)

        return parse_players(data)


def parse_players(data):
    if (
        len(data) < 6
        or data[:4] != b"\xff\xff\xff\xff"
        or data[4:5] != b"D"
    ):
        raise ValueError("invalid A2S_PLAYER response")

    count = data[5]
    p = 6
    players = []

    for _ in range(count):
        if p >= len(data):
            break

        index = data[p]
        p += 1

        name, p = cstr(data, p)

        if p + 8 > len(data):
            break

        score = struct.unpack_from("<i", data, p)[0]
        p += 4

        duration = struct.unpack_from("<f", data, p)[0]
        p += 4

        players.append({
            "index": index,
            "name": name,
            "score": score,
            "duration": round(max(0.0, duration), 1)
        })

    return players


def main():
    seeds = json.loads(
        SEED.read_text(encoding="utf-8")
    )

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
            except Exception as e:
                # Server can allow A2S_INFO while blocking A2S_PLAYER.
                print(
                    item["ip"],
                    "PLAYER QUERY FAILED:",
                    str(e)[:120]
                )
                row["playerList"] = []

        except Exception as e:
            row["error"] = str(e)[:120]

        results.append(row)

        print(
            item["ip"],
            "ONLINE" if row["online"] else "OFFLINE",
            row["players"],
            "/",
            row["maxPlayers"],
            row.get("error", "")
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)

    OUT.write_text(
        json.dumps(
            {
                "updatedAt": int(time.time()),
                "servers": results
            },
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )


if __name__ == "__main__":
    main()
