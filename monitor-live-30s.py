#!/usr/bin/env python3
# UZB SERVERS — live CS 1.6 monitor
# 1s ping + 30s A2S_INFO/A2S_PLAYER snapshots.
#
# IMPORTANT:
# - This file is for the next monitoring phase.
# - Keep your existing monitor.py unchanged until this one is tested.
# - MONITOR_TOKEN must be configured before D1 POSTs can work.

import json
import os
import socket
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

MONITOR_API = os.getenv(
    "MONITOR_API",
    "https://uzbservers.uzbservers.workers.dev/api/server-history",
)
MONITOR_TOKEN = os.getenv("MONITOR_TOKEN", "")

INFO_INTERVAL = 30.0
PING_INTERVAL = 1.0
SOCKET_TIMEOUT = 1.2

SERVERS = [
    {"name": "CSZONE.UZ - Public #1", "ip": "195.158.11.77", "port": 27015},
    {"name": "CSZONE.UZ - Public #2", "ip": "195.158.11.77", "port": 27016},
    {"name": "CSZONE.UZ - Clanwar #1", "ip": "195.158.11.77", "port": 27017},
    {"name": "CSZONE.UZ - Clanwar #2", "ip": "195.158.11.77", "port": 27018},
    {"name": "NumberOne[UZ]-Public #1", "ip": "83.69.139.164", "port": 27016},
    {"name": "NumberOne[UZ]-Public #2", "ip": "83.69.139.164", "port": 27022},
    {"name": "NumberOne[UZ]-CSDM #1", "ip": "83.69.139.164", "port": 27020},
    {"name": "NUMBERONE UZBEKISTAN", "ip": "83.69.139.164", "port": 27015},
    {"name": "TIMCS.UZ Public #1", "ip": "195.158.4.109", "port": 27015},
    {"name": "UZB ARENA", "ip": "157.22.130.26", "port": 27015},
    {"name": "PROCS.UZ", "ip": "195.158.4.108", "port": 27777},
    {"name": "ONECS.UZ Public #1", "ip": "185.228.90.26", "port": 27002},
    {"name": "IHOST.UZ MIX", "ip": "83.69.139.164", "port": 27014},
    {"name": "WEIT CS Public", "ip": "84.54.82.234", "port": 27047},
    {"name": "CSLOVE.UZ [PUBLIC #1]", "ip": "84.54.82.234", "port": 27015},
]


def cstring(data, pos):
    end = data.find(b"\x00", pos)
    if end < 0:
        raise ValueError("unterminated string")
    return data[pos:end].decode("utf-8", "replace"), end + 1


def parse_source_info(data, ping):
    if len(data) < 6 or data[:4] != b"\xff\xff\xff\xff" or data[4] != 0x49:
        raise ValueError("not Source A2S_INFO")

    pos = 5
    pos += 1  # protocol
    name, pos = cstring(data, pos)
    map_name, pos = cstring(data, pos)
    _, pos = cstring(data, pos)  # folder
    _, pos = cstring(data, pos)  # game

    if pos + 2 > len(data):
        raise ValueError("short Source A2S_INFO response")

    players = data[pos]
    max_players = data[pos + 1]

    return {
        "server_name": name,
        "map": map_name,
        "players": players,
        "max_players": max_players,
        "ping": ping,
        "online": True,
    }


def parse_goldsrc_info(data, ping):
    if len(data) < 6 or data[:4] != b"\xff\xff\xff\xff" or data[4] != 0x6d:
        raise ValueError("not GoldSrc A2S_INFO")

    pos = 5
    _, pos = cstring(data, pos)  # address
    name, pos = cstring(data, pos)
    map_name, pos = cstring(data, pos)
    _, pos = cstring(data, pos)  # folder
    _, pos = cstring(data, pos)  # game

    if pos + 7 > len(data):
        raise ValueError("short GoldSrc response")

    players = data[pos]
    max_players = data[pos + 1]

    # protocol, server type, platform, password, mod
    pos += 5

    if pos > len(data):
        raise ValueError("short GoldSrc response")

    mod = data[pos - 1]

    if mod == 1:
        _, pos = cstring(data, pos)  # website
        _, pos = cstring(data, pos)  # download URL

        if pos + 10 > len(data):
            raise ValueError("short GoldSrc mod block")

        pos += 8  # version + size
        pos += 2  # multiplayer_only + custom DLL

    return {
        "server_name": name,
        "map": map_name,
        "players": players,
        "max_players": max_players,
        "ping": ping,
        "online": True,
    }


def parse_player(data):
    if len(data) < 6 or data[:4] != b"\xff\xff\xff\xff" or data[4] != 0x44:
        raise ValueError("not A2S_PLAYER")

    count = data[5]
    pos = 6
    players = []

    for _ in range(count):
        if pos >= len(data):
            break

        index = data[pos]
        pos += 1

        name, pos = cstring(data, pos)

        if pos + 8 > len(data):
            break

        score = struct.unpack_from("<i", data, pos)[0]
        pos += 4

        duration = struct.unpack_from("<f", data, pos)[0]
        pos += 4

        players.append({
            "name": name,
            "score": score,
            "duration": duration,
            "index": index,
        })

    return players


def info_query(server):
    host = server["ip"]
    port = server["port"]

    packet = b"\xff\xff\xff\xff\x54Source Engine Query\x00"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    started = time.perf_counter()

    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(65535)

        ping = max(1, round((time.perf_counter() - started) * 1000))

        if len(data) >= 5 and data[4] == 0x49:
            result = parse_source_info(data, ping)

        elif len(data) >= 5 and data[4] == 0x6d:
            # Some GoldSrc servers return a legacy packet first and
            # a newer Source-style response shortly afterwards.
            sock.settimeout(0.35)

            try:
                extra, _ = sock.recvfrom(65535)

                if len(extra) >= 5 and extra[4] == 0x49:
                    result = parse_source_info(extra, ping)
                else:
                    result = parse_goldsrc_info(data, ping)

            except socket.timeout:
                result = parse_goldsrc_info(data, ping)

        else:
            raise ValueError(
                f"unexpected A2S_INFO response: 0x{data[4]:02x}"
            )

        result["ip"] = f"{host}:{port}"
        result["server_name"] = (
            result.get("server_name") or server["name"]
        )

        return result

    finally:
        sock.close()


def player_query(server):
    host = server["ip"]
    port = server["port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    try:
        # Ask for the player challenge.
        sock.sendto(
            b"\xff\xff\xff\xff\x55\xff\xff\xff\xff",
            (host, port),
        )

        data, _ = sock.recvfrom(65535)

        if len(data) >= 9 and data[4] == 0x41:
            challenge = data[5:9]

            sock.sendto(
                b"\xff\xff\xff\xff\x55" + challenge,
                (host, port),
            )

            data, _ = sock.recvfrom(65535)

        return parse_player(data)

    except Exception:
        return []

    finally:
        sock.close()


def ping_query(server):
    host = server["ip"]
    port = server["port"]

    packet = b"\xff\xff\xff\xff\x54Source Engine Query\x00"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    started = time.perf_counter()

    try:
        sock.sendto(packet, (host, port))
        sock.recvfrom(65535)

        return max(
            1,
            round((time.perf_counter() - started) * 1000),
        )

    except Exception:
        return None

    finally:
        sock.close()


def post_snapshot(snapshot):
    if not MONITOR_TOKEN:
        print(
            "MONITOR_TOKEN is not set; "
            "snapshot was NOT sent to D1."
        )
        return False

    body = json.dumps({
        "servers": snapshot,
        "updatedAt": int(time.time()),
    }).encode()

    request = urllib.request.Request(
        MONITOR_API,
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {MONITOR_TOKEN}",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:
            response.read()

        return True

    except Exception as exc:
        print(f"D1 POST failed: {exc}")
        return False


def run_snapshot():
    results = []

    with ThreadPoolExecutor(
        max_workers=min(16, len(SERVERS))
    ) as pool:

        futures = {
            pool.submit(info_query, server): server
            for server in SERVERS
        }

        for future in as_completed(futures):
            server = futures[future]

            base = {
                "name": server["name"],
                "ip": f'{server["ip"]}:{server["port"]}',
                "online": False,
                "players": 0,
                "max_players": 0,
                "ping": None,
                "map": "",
                "playerList": [],
                "playerScores": [],
            }

            try:
                base.update(future.result())

                base["name"] = (
                    base.get("server_name")
                    or server["name"]
                )

                base.pop("server_name", None)

                player_list = player_query(server)

                base["playerList"] = player_list

                base["playerScores"] = [
                    {
                        "name": player["name"],
                        "score": player["score"],
                    }
                    for player in player_list
                ]

                # A2S_PLAYER is the more detailed player source.
                # Keep the A2S_INFO count as the server count if available.
                base["players"] = max(
                    int(base.get("players") or 0),
                    len(player_list),
                )

            except Exception as exc:
                base["error"] = str(exc)

            results.append(base)

    results.sort(key=lambda item: item["ip"])

    return results


def live_ping_cycle(snapshot):
    ping_map = {}

    with ThreadPoolExecutor(
        max_workers=min(16, len(SERVERS))
    ) as pool:

        futures = {
            pool.submit(ping_query, server): server
            for server in SERVERS
        }

        for future in as_completed(futures):
            server = futures[future]

            address = f'{server["ip"]}:{server["port"]}'

            try:
                ping_map[address] = future.result()
            except Exception:
                ping_map[address] = None

    for item in snapshot:
        item["ping"] = ping_map.get(
            item["ip"],
            item.get("ping"),
        )

    return snapshot


def main():
    print("======================================")
    print(" UZB SERVERS — LIVE MONITOR")
    print("======================================")
    print("1 second  -> live ping")
    print("30 seconds -> A2S_INFO + A2S_PLAYER")
    print("30 seconds -> D1 history snapshot")
    print("--------------------------------------")

    snapshot = []
    next_snapshot = 0.0

    while True:
        started = time.monotonic()

        if not snapshot or started >= next_snapshot:
            snapshot = run_snapshot()

            post_snapshot(snapshot)

            print(
                f"[{time.strftime('%H:%M:%S')}] "
                f"30s snapshot: {len(snapshot)} servers"
            )

            next_snapshot = started + INFO_INTERVAL

        # Live ping is intentionally NOT written to D1 every second.
        # The next Worker/dashboard phase will expose live ping separately.
        snapshot = live_ping_cycle(snapshot)

        elapsed = time.monotonic() - started

        time.sleep(
            max(
                0.05,
                PING_INTERVAL - elapsed,
            )
        )


if __name__ == "__main__":
    main()
