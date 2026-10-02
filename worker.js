/* =========================================================
   SERVER MONITORING HISTORY — ADD TO worker.js
   Place this block BEFORE:
   /* =========================================================
      API ROUTER
   ========================================================= */
========================================================= */

async function serverHistory(request, env) {
  if (!env.DB) {
    return json({ error: "D1 database binding topilmadi." }, 500);
  }

  /* GET — tarixni o‘qish */
  if (request.method === "GET") {
    const url = new URL(request.url);
    const ip = url.searchParams.get("ip");

    const rawHours = Number(url.searchParams.get("hours") || 24);
    const hours = Math.max(
      1,
      Math.min(
        168,
        Number.isFinite(rawHours) ? rawHours : 24
      )
    );

    const since =
      Math.floor(Date.now() / 1000) -
      hours * 60 * 60;

    let result;

    if (ip) {
      result = await env.DB.prepare(`
        SELECT
          server_ip AS ip,
          server_name AS name,
          checked_at AS checkedAt,
          online,
          players,
          max_players AS maxPlayers,
          ping,
          map
        FROM server_history
        WHERE server_ip = ?
          AND checked_at >= ?
        ORDER BY checked_at ASC
        LIMIT 5000
      `)
        .bind(ip, since)
        .all();

    } else {
      result = await env.DB.prepare(`
        SELECT
          server_ip AS ip,
          server_name AS name,
          checked_at AS checkedAt,
          online,
          players,
          max_players AS maxPlayers,
          ping,
          map
        FROM server_history
        WHERE checked_at >= ?
        ORDER BY checked_at ASC
        LIMIT 10000
      `)
        .bind(since)
        .all();
    }

    return json({
      ok: true,
      hours,
      points: result.results || []
    });
  }


  /* POST — GitHub Actions monitor natijasini D1 ga yozish */
  if (request.method === "POST") {
    const auth =
      request.headers.get("authorization") || "";

    const expected =
      env.MONITOR_TOKEN;

    if (
      !expected ||
      auth !== `Bearer ${expected}`
    ) {
      return json({
        error: "Monitor ruxsati talab qilinadi."
      }, 401);
    }

    const body =
      await request.json().catch(() => null);

    const servers =
      Array.isArray(body?.servers)
        ? body.servers
        : [];

    if (!servers.length) {
      return json({
        error: "Server ma’lumotlari topilmadi."
      }, 400);
    }

    const checkedAt =
      Number(body?.updatedAt) ||
      Math.floor(Date.now() / 1000);

    const statements =
      servers.map(server =>
        env.DB.prepare(`
          INSERT INTO server_history
            (
              server_ip,
              server_name,
              checked_at,
              online,
              players,
              max_players,
              ping,
              map
            )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          String(server.ip || "")
            .slice(0, 100),

          String(server.name || "")
            .slice(0, 160),

          checkedAt,

          server.online ? 1 : 0,

          Math.max(
            0,
            Number(server.players) || 0
          ),

          Math.max(
            0,
            Number(server.maxPlayers) || 0
          ),

          Number.isFinite(
            Number(server.ping)
          )
            ? Number(server.ping)
            : null,

          String(server.map || "—")
            .slice(0, 100)
        )
      );

    await env.DB.batch(statements);

    return json({
      ok: true,
      saved: statements.length,
      checkedAt
    });
  }


  return json({
    error: "Method qo‘llab-quvvatlanmaydi."
  }, 405);
}


/* =========================================================
   API ROUTER ICHIGA QO‘SHILADI
   "/* REGISTER */" dan OLDIN joylashtiring.
========================================================= */

  /* SERVER HISTORY */

  if (
    (
      request.method === "GET" ||
      request.method === "POST"
    ) &&
    url.pathname === "/api/server-history"
  ) {
    return serverHistory(
      request,
      env
    );
  }
