#!/usr/bin/env python3

import base64
import json
import os
import socket
import struct
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================================================
# UZB SERVERS — RAILWAY LIVE MONITOR
# Serverlar har 60 soniyada tekshiriladi
# =========================================================

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

GITHUB_REPO = os.getenv(
    "GITHUB_REPO",
    "AzizjonLutfullayev/uzbservers-web"
).strip()

GITHUB_BRANCH = os.getenv(
    "GITHUB_BRANCH",
    "main"
).strip()

# HAR 60 SONIYA
INTERVAL = max(
    60,
    int(os.getenv("INTERVAL", "60"))
)

TIMEOUT = 2.0

FILE_PATH = "public/servers.json"


# =========================================================
# MONITORING SERVERLAR
# =========================================================

SERVERS = [

    {
        "name": "CSZONE.UZ - Public #1",
        "ip": "195.158.11.77",
        "port": 27015
    },

    {
        "name": "CSZONE.UZ - Public #2",
        "ip": "195.158.11.77",
        "port": 27016
    },

    {
        "name": "CSZONE.UZ - Clanwar #1",
        "ip": "195.158.11.77",
        "port": 27017
    },

    {
        "name": "CSZONE.UZ - Clanwar #2",
        "ip": "195.158.11.77",
        "port": 27018
    },

    {
        "name": "NumberOne[UZ]-Public #1",
        "ip": "83.69.139.164",
        "port": 27016
    },

    {
        "name": "NumberOne[UZ]-Public #2",
        "ip": "83.69.139.164",
        "port": 27022
    },

    {
        "name": "NumberOne[UZ]-CSDM #1",
        "ip": "83.69.139.164",
        "port": 27020
    },

    {
        "name": "NUMBERONE UZBEKISTAN",
        "ip": "83.69.139.164",
        "port": 27015
    },

    {
        "name": "TIMCS.UZ Public #1",
        "ip": "195.158.4.109",
        "port": 27015
    },

    {
        "name": "UZB ARENA",
        "ip": "157.22.130.26",
        "port": 27015
    },

    {
        "name": "PROCS.UZ",
        "ip": "195.158.4.108",
        "port": 27777
    },

    {
        "name": "ONECS.UZ Public #1",
        "ip": "185.228.90.26",
        "port": 27002
    },

    {
        "name": "IHOST.UZ MIX",
        "ip": "83.69.139.164",
        "port": 27014
    },

    {
        "name": "WEIT CS Public",
        "ip": "84.54.82.234",
        "port": 27047
    },

    {
        "name": "CSLOVE.UZ [PUBLIC #1]",
        "ip": "84.54.82.234",
        "port": 27015
    }

]


# =========================================================
# STRING PARSER
# =========================================================

def cstr(data, pos):

    end = data.find(
        b"\x00",
        pos
    )

    if end < 0:
        raise ValueError(
            "unterminated string"
        )

    return (
        data[pos:end].decode(
            "utf-8",
            "replace"
        ),
        end + 1
    )


# =========================================================
# A2S INFO
# =========================================================

def query_info(server):

    addr = (
        server["ip"],
        server["port"]
    )

    packet = (
        b"\xff\xff\xff\xff"
        b"\x54Source Engine Query\x00"
    )

    started = time.perf_counter()

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    ) as s:

        s.settimeout(TIMEOUT)

        s.sendto(
            packet,
            addr
        )

        data, _ = s.recvfrom(
            65535
        )

    ping = max(
        1,
        round(
            (time.perf_counter() - started)
            * 1000
        )
    )

    if (
        len(data) < 6
        or data[:4] != b"\xff\xff\xff\xff"
    ):
        raise ValueError(
            "invalid A2S_INFO"
        )

    typ = data[4]


    # -----------------------------------------------------
    # SOURCE
    # -----------------------------------------------------

    if typ == 0x49:

        pos = 6

        name, pos = cstr(
            data,
            pos
        )

        map_name, pos = cstr(
            data,
            pos
        )

        _, pos = cstr(
            data,
            pos
        )

        _, pos = cstr(
            data,
            pos
        )

        if pos + 2 > len(data):

            raise ValueError(
                "short Source A2S_INFO"
            )

        players = data[pos]

        max_players = data[pos + 1]


    # -----------------------------------------------------
    # GOLDSRC / CS 1.6
    # -----------------------------------------------------

    elif typ == 0x6d:

        pos = 5

        _, pos = cstr(
            data,
            pos
        )

        name, pos = cstr(
            data,
            pos
        )

        map_name, pos = cstr(
            data,
            pos
        )

        _, pos = cstr(
            data,
            pos
        )

        _, pos = cstr(
            data,
            pos
        )

        if pos + 7 > len(data):

            raise ValueError(
                "short GoldSrc A2S_INFO"
            )

        players = data[pos]

        max_players = data[pos + 1]


    else:

        raise ValueError(
            f"unexpected A2S_INFO type 0x{typ:02x}"
        )


    return {

        "name":
            name
            or server["name"],

        "map":
            map_name,

        "players":
            int(players),

        "maxPlayers":
            int(max_players),

        "ping":
            ping,

        "online":
            True

    }


# =========================================================
# A2S PLAYER
# =========================================================

def query_players(server):

    addr = (
        server["ip"],
        server["port"]
    )

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    ) as s:

        s.settimeout(
            TIMEOUT
        )

        # First request
        s.sendto(
            b"\xff\xff\xff\xff"
            b"\x55"
            b"\xff\xff\xff\xff",
            addr
        )

        data, _ = s.recvfrom(
            65535
        )


        # Challenge received
        if (
            len(data) >= 9
            and data[4] == 0x41
        ):

            challenge = data[5:9]

            s.sendto(
                b"\xff\xff\xff\xff"
                b"\x55"
                + challenge,
                addr
            )

            data, _ = s.recvfrom(
                65535
            )


    if (
        len(data) < 6
        or data[:4] != b"\xff\xff\xff\xff"
        or data[4] != 0x44
    ):

        raise ValueError(
            "invalid A2S_PLAYER"
        )


    count = data[5]

    pos = 6

    players = []


    for _ in range(count):

        if pos >= len(data):
            break

        index = data[pos]

        pos += 1


        name, pos = cstr(
            data,
            pos
        )


        if pos + 8 > len(data):
            break


        score = struct.unpack_from(
            "<i",
            data,
            pos
        )[0]

        pos += 4


        duration = struct.unpack_from(
            "<f",
            data,
            pos
        )[0]

        pos += 4


        players.append({

            "index":
                index,

            "name":
                name,

            "score":
                score,

            "duration":
                round(
                    max(
                        0.0,
                        duration
                    ),
                    1
                )

        })


    return players


# =========================================================
# CHECK ONE SERVER
# =========================================================

def check(server):

    row = {

        "name":
            server["name"],

        "ip":
            f'{server["ip"]}:{server["port"]}',

        "online":
            False,

        "players":
            0,

        "maxPlayers":
            0,

        "map":
            "—",

        "ping":
            None,

        "playerList":
            []

    }


    try:

        row.update(
            query_info(server)
        )


        try:

            row["playerList"] = (
                query_players(server)
            )


            row["players"] = max(

                row["players"],

                len(
                    row["playerList"]
                )

            )


        except Exception as e:

            row["playerError"] = str(e)[
                :120
            ]


    except Exception as e:

        row["error"] = str(e)[
            :120
        ]


    return row


# =========================================================
# GITHUB API
# =========================================================

def github_request(
    method,
    url,
    body=None
):

    if not GITHUB_TOKEN:

        raise RuntimeError(
            "GITHUB_TOKEN is not set."
        )


    headers = {

        "Authorization":
            f"Bearer {GITHUB_TOKEN}",

        "Accept":
            "application/vnd.github+json",

        "X-GitHub-Api-Version":
            "2022-11-28",

        "User-Agent":
            "uzbservers-railway-monitor"

    }


    data = None


    if body is not None:

        data = json.dumps(
            body,
            ensure_ascii=False
        ).encode()


        headers[
            "Content-Type"
        ] = "application/json"


    req = urllib.request.Request(

        url,

        data=data,

        method=method,

        headers=headers

    )


    with urllib.request.urlopen(
        req,
        timeout=20
    ) as r:

        return json.loads(
            r.read().decode()
        )


# =========================================================
# PUBLISH SERVERS.JSON
# =========================================================

def publish(snapshot):

    api = (
        f"https://api.github.com/repos/"
        f"{GITHUB_REPO}/contents/"
        f"{FILE_PATH}"
        f"?ref="
        f"{urllib.parse.quote(GITHUB_BRANCH)}"
    )


    current = github_request(
        "GET",
        api
    )


    content = {

        "updatedAt":
            int(time.time()),

        "servers":
            snapshot

    }


    encoded = base64.b64encode(

        json.dumps(
            content,
            ensure_ascii=False,
            indent=2
        ).encode()

    ).decode()


    payload = {

        "message":
            "Update CS 1.6 server status",

        "content":
            encoded,

        "branch":
            GITHUB_BRANCH,

        "sha":
            current["sha"]

    }


    github_request(

        "PUT",

        api,

        payload

    )


# =========================================================
# MAIN LOOP
# =========================================================

def main():

    print(
        f"UZB SERVERS Railway monitor | "
        f"{len(SERVERS)} servers | "
        f"every {INTERVAL}s"
    )


    while True:

        started = time.time()


        # Parallel server checking
        with ThreadPoolExecutor(
            max_workers=min(
                16,
                len(SERVERS)
            )
        ) as pool:

            futures = [

                pool.submit(
                    check,
                    server
                )

                for server in SERVERS

            ]


            snapshot = [

                future.result()

                for future in as_completed(
                    futures
                )

            ]


        snapshot.sort(
            key=lambda x: x["ip"]
        )


        try:

            publish(
                snapshot
            )


            online = sum(

                1

                for server in snapshot

                if server["online"]

            )


            players = sum(

                int(
                    server.get(
                        "players"
                    )
                    or 0
                )

                for server in snapshot

            )


            print(

                f"[{time.strftime('%H:%M:%S')}] "
                f"published: "
                f"{online}/{len(snapshot)} "
                f"online, "
                f"{players} players"

            )


        except Exception as e:

            print(
                f"PUBLISH ERROR: {e}"
            )


        # =================================================
        # NEXT CHECK — 60 SECONDS
        # =================================================

        elapsed = (
            time.time()
            - started
        )

        time.sleep(
            max(
                1,
                INTERVAL - elapsed
            )
        )


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    main()
