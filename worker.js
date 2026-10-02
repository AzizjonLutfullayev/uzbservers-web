const SESSION_TTL = 60 * 60 * 24 * 7;
const PBKDF2_ITERATIONS = 100000;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function bytesToB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(value) {
  const s = atob(value);
  return Uint8Array.from(s, c => c.charCodeAt(0));
}

function randomToken(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);

  return [...a]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToB64(salt)}$${bytesToB64(
    new Uint8Array(bits)
  )}`;
}

async function verifyPassword(password, stored) {
  try {
    const [scheme, iterations, salt64, hash64] = stored.split("$");

    if (scheme !== "pbkdf2") return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: b64ToBytes(salt64),
        iterations: Number(iterations),
        hash: "SHA-256"
      },
      key,
      256
    );

    const a = new Uint8Array(bits);
    const b = b64ToBytes(hash64);

    if (a.length !== b.length) return false;

    let diff = 0;

    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }

    return diff === 0;
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

function sessionCookie(token, maxAge = SESSION_TTL) {
  return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearSessionCookie() {
  return "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}


/* =========================================================
   CURRENT USER
========================================================= */

async function currentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) return null;

  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(`
    SELECT
      users.id,
      users.username,
      users.email,
      users.role,
      users.is_banned
    FROM sessions
    JOIN users
      ON users.id = sessions.user_id
    WHERE
      sessions.id = ?
      AND sessions.expires_at > ?
  `)
    .bind(token, now)
    .first();

  return row || null;
}


/* =========================================================
   REGISTER
========================================================= */

async function register(request, env) {
  const body = await request.json().catch(() => null);

  if (!body) {
    return json({
      error: "Noto‘g‘ri JSON."
    }, 400);
  }

  const username = String(body.username || "").trim();

  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) {
    return json({
      error:
        "Login 3–24 belgidan iborat bo‘lsin: harf, raqam yoki _."
    }, 400);
  }

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.length > 160
  ) {
    return json({
      error: "Email manzili noto‘g‘ri."
    }, 400);
  }

  if (password.length < 8 || password.length > 128) {
    return json({
      error: "Parol 8–128 belgidan iborat bo‘lsin."
    }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE username = ?
       OR email = ?
    LIMIT 1
  `)
    .bind(username, email)
    .first();

  if (existing) {
    return json({
      error:
        "Bu login yoki email allaqachon ro‘yxatdan o‘tgan."
    }, 409);
  }

  const passwordHash = await hashPassword(password);

  const now = Math.floor(Date.now() / 1000);

  try {
    const result = await env.DB.prepare(`
      INSERT INTO users
        (
          username,
          email,
          password_hash,
          created_at
        )
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        username,
        email,
        passwordHash,
        now
      )
      .run();

    const userId = result.meta.last_row_id;

    const token = randomToken(32);

    const expires = now + SESSION_TTL;

    await env.DB.prepare(`
      INSERT INTO sessions
        (
          id,
          user_id,
          expires_at,
          created_at
        )
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        token,
        userId,
        expires,
        now
      )
      .run();

    await env.DB.prepare(`
      INSERT INTO profiles
        (
          user_id,
          updated_at
        )
      VALUES (?, ?)
    `)
      .bind(userId, now)
      .run();

    return json(
      {
        ok: true,
        user: {
          id: userId,
          username,
          email
        }
      },
      201,
      {
        "Set-Cookie": sessionCookie(token)
      }
    );

  } catch (error) {
    return json({
      error:
        "Akkaunt yaratishda xatolik yuz berdi."
    }, 500);
  }
}


/* =========================================================
   LOGIN
========================================================= */

async function login(request, env) {
  const body = await request.json().catch(() => null);

  if (!body) {
    return json({
      error: "Noto‘g‘ri JSON."
    }, 400);
  }

  const loginValue = String(body.login || "").trim();

  const password = String(body.password || "");

  const user = await env.DB.prepare(`
    SELECT
      id,
      username,
      email,
      password_hash,
      role,
      is_banned
    FROM users
    WHERE username = ?
       OR email = ?
    LIMIT 1
  `)
    .bind(
      loginValue,
      loginValue.toLowerCase()
    )
    .first();

  if (
    !user ||
    !(await verifyPassword(
      password,
      user.password_hash
    ))
  ) {
    return json({
      error: "Login yoki parol noto‘g‘ri."
    }, 401);
  }

  if (Number(user.is_banned) === 1) {
    return json({
      error: "Akkauntingiz sayt ma’muriyati tomonidan cheklangan."
    }, 403);
  }

  const now = Math.floor(Date.now() / 1000);

  const token = randomToken(32);

  const expires = now + SESSION_TTL;

  await env.DB.prepare(`
    INSERT INTO sessions
      (
        id,
        user_id,
        expires_at,
        created_at
      )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      token,
      user.id,
      expires,
      now
    )
    .run();

  return json(
    {
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_banned: !!user.is_banned
      }
    },
    200,
    {
      "Set-Cookie": sessionCookie(token)
    }
  );
}


/* =========================================================
   LOGOUT
========================================================= */

async function logout(request, env) {
  const token = getCookie(request, "session");

  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(token)
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": clearSessionCookie()
    }
  );
}


/* =========================================================
   ME
========================================================= */

async function me(request, env) {
  const user = await currentUser(request, env);

  return json({
    authenticated: !!user,

    user: user
      ? {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          is_banned: !!user.is_banned
        }
      : null
  });
}


/* =========================================================
   PROFILE
========================================================= */

async function profile(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return json({
      error: "Kirish talab qilinadi."
    }, 401);
  }

  if (request.method === "GET") {

    const p = await env.DB.prepare(`
      SELECT
        first_name,
        last_name,
        telegram,
        phone,
        steam_id,
        server_nickname,
        avatar_url
      FROM profiles
      WHERE user_id = ?
    `)
      .bind(user.id)
      .first();

    return json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      },

      profile:
        p || {
          first_name: "",
          last_name: "",
          telegram: "",
          phone: "",
          steam_id: "",
          server_nickname: "",
          avatar_url: ""
        }
    });
  }

  if (request.method !== "PUT") {
    return json({
      error: "Method qo‘llab-quvvatlanmaydi."
    }, 405);
  }

  const body = await request
    .json()
    .catch(() => null);

  if (!body) {
    return json({
      error: "Noto‘g‘ri JSON."
    }, 400);
  }

  const clean = {

    first_name:
      String(body.first_name || "")
        .trim()
        .slice(0, 80),

    last_name:
      String(body.last_name || "")
        .trim()
        .slice(0, 80),

    telegram:
      String(body.telegram || "")
        .trim()
        .slice(0, 100),

    phone:
      String(body.phone || "")
        .trim()
        .slice(0, 30),

    steam_id:
      String(body.steam_id || "")
        .trim()
        .slice(0, 64),

    server_nickname:
      String(body.server_nickname || "")
        .trim()
        .slice(0, 32),

    avatar_url:
      String(body.avatar_url || "")
        .trim()
        .slice(0, 100000)
  };

  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO profiles
      (
        user_id,
        first_name,
        last_name,
        telegram,
        phone,
        steam_id,
        server_nickname,
        avatar_url,
        updated_at
      )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

    ON CONFLICT(user_id)
    DO UPDATE SET

      first_name = excluded.first_name,

      last_name = excluded.last_name,

      telegram = excluded.telegram,

      phone = excluded.phone,

      steam_id = excluded.steam_id,

      server_nickname =
        excluded.server_nickname,

      avatar_url =
        excluded.avatar_url,

      updated_at =
        excluded.updated_at
  `)
    .bind(
      user.id,
      clean.first_name,
      clean.last_name,
      clean.telegram,
      clean.phone,
      clean.steam_id,
      clean.server_nickname,
      clean.avatar_url,
      now
    )
    .run();

  return json({
    ok: true,
    profile: clean
  });
}


/* =========================================================
   PRESENCE / ONLINE USERS
========================================================= */

async function presence(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return json({
      error: "Kirish talab qilinadi."
    }, 401);
  }

  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO user_presence
      (user_id, last_seen)
    VALUES (?, ?)

    ON CONFLICT(user_id)
    DO UPDATE SET
      last_seen = excluded.last_seen
  `)
    .bind(user.id, now)
    .run();

  return json({
    ok: true,
    last_seen: now
  });
}


/* =========================================================
   CHAT
========================================================= */

async function chat(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return json({
      error: "Kirish talab qilinadi."
    }, 401);
  }

  if (user.is_banned) {
    return json({
      error: "Akkauntingiz cheklangan."
    }, 403);
  }


  /* =======================================================
     GET CHAT MESSAGES
  ======================================================= */

  if (request.method === "GET") {

    const url = new URL(request.url);

    let limit = Number(
      url.searchParams.get("limit") || 100
    );

    if (!Number.isFinite(limit)) {
      limit = 100;
    }

    limit = Math.max(
      1,
      Math.min(
        100,
        Math.floor(limit)
      )
    );

    const rows = await env.DB.prepare(`
      SELECT
        chat_messages.id,
        chat_messages.user_id,
        chat_messages.message,
        chat_messages.created_at,

        users.username,
        users.role,

        profiles.first_name,
        profiles.avatar_url

      FROM chat_messages

      JOIN users
        ON users.id = chat_messages.user_id

      LEFT JOIN profiles
        ON profiles.user_id = users.id

      ORDER BY chat_messages.id DESC

      LIMIT ?
    `)
      .bind(limit)
      .all();

    const messages =
      (rows.results || []).reverse();

    return json({
      messages
    });
  }


  /* =======================================================
     POST NEW CHAT MESSAGE
  ======================================================= */

  if (request.method === "POST") {

    const body =
      await request.json().catch(() => null);

    if (!body) {
      return json({
        error: "Noto‘g‘ri JSON."
      }, 400);
    }

    const message =
      String(body.message || "")
        .trim();

    if (!message) {
      return json({
        error: "Xabar bo‘sh bo‘lishi mumkin emas."
      }, 400);
    }

    if (message.length > 1000) {
      return json({
        error: "Xabar 1000 belgidan oshmasin."
      }, 400);
    }

    const now =
      Math.floor(Date.now() / 1000);

    const result = await env.DB.prepare(`
      INSERT INTO chat_messages
        (
          user_id,
          message,
          created_at
        )
      VALUES (?, ?, ?)
    `)
      .bind(
        user.id,
        message,
        now
      )
      .run();

    return json({
      ok: true,
      id: result.meta.last_row_id
    }, 201);
  }


  /* =======================================================
     PUT EDIT CHAT MESSAGE
  ======================================================= */

  if (request.method === "PUT") {

    const body =
      await request.json().catch(() => null);

    if (!body) {
      return json({
        error: "Noto‘g‘ri JSON."
      }, 400);
    }

    const messageId =
      Number(body.message_id);

    const message =
      String(body.message || "")
        .trim();

    if (
      !Number.isInteger(messageId) ||
      messageId <= 0
    ) {
      return json({
        error: "Xabar ID noto‘g‘ri."
      }, 400);
    }

    if (!message) {
      return json({
        error: "Xabar bo‘sh bo‘lishi mumkin emas."
      }, 400);
    }

    if (message.length > 1000) {
      return json({
        error: "Xabar 1000 belgidan oshmasin."
      }, 400);
    }

    const target =
      await env.DB.prepare(`
        SELECT
          id,
          user_id,
          message
        FROM chat_messages
        WHERE id = ?
        LIMIT 1
      `)
        .bind(messageId)
        .first();

    if (!target) {
      return json({
        error: "Xabar topilmadi."
      }, 404);
    }

    /*
      Faqat xabar egasi o‘z xabarini
      tahrirlashi mumkin.
    */

    if (
      Number(target.user_id) !==
      Number(user.id)
    ) {
      return json({
        error:
          "Faqat o‘zingiz yozgan xabarni tahrirlashingiz mumkin."
      }, 403);
    }

    await env.DB.prepare(`
      UPDATE chat_messages
      SET message = ?
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(
        message,
        messageId,
        user.id
      )
      .run();

    return json({
      ok: true,
      message_id: messageId,
      message
    });
  }


  return json({
    error:
      "Method qo‘llab-quvvatlanmaydi."
  }, 405);
}


/* =========================================================
   ONLINE USERS
========================================================= */

/* =========================================================
   ONLINE USERS
========================================================= */

async function onlineUsers(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return json({
      error: "Kirish talab qilinadi."
    }, 401);
  }

  const now = Math.floor(Date.now() / 1000);

  // 90 sekund ichida heartbeat yuborganlar online
  const onlineAfter = now - 90;

  const rows = await env.DB.prepare(`
    SELECT
      users.id,
      users.username,
      users.role,
      users.is_banned,

      profiles.first_name,
      profiles.last_name,
      profiles.avatar_url,

      user_presence.last_seen

    FROM user_presence

    JOIN users
      ON users.id = user_presence.user_id

    LEFT JOIN profiles
      ON profiles.user_id = users.id

    WHERE user_presence.last_seen >= ?
      AND users.is_banned = 0

    ORDER BY user_presence.last_seen DESC

    LIMIT 200
  `)
    .bind(onlineAfter)
    .all();

  const users = rows.results || [];

  return json({
    users: users,
    total: users.length
  });
}
  const user = await currentUser(request, env);

  if (!user) {
    return json({
      error: "Kirish talab qilinadi."
    }, 401);
  }

  const now =
    Math.floor(Date.now() / 1000);

  const onlineAfter =
    now - 90;

  const rows = await env.DB.prepare(`
    SELECT
      users.id,
      users.username,
      users.role,

      profiles.avatar_url,

      user_presence.last_seen

    FROM user_presence

    JOIN users
      ON users.id = user_presence.user_id

    LEFT JOIN profiles
      ON profiles.user_id = users.id

    WHERE user_presence.last_seen >= ?
      AND users.is_banned = 0

    ORDER BY user_presence.last_seen DESC

    LIMIT 200
  `)
    .bind(onlineAfter)
    .all();

  return json({
    online: rows.results || [],
    count: (rows.results || []).length
  });
}


/* =========================================================
   ADMIN HELPERS
========================================================= */

function isAdmin(user) {
  return !!user &&
    (
      user.role === "admin" ||
      user.role === "gl_admin"
    );
}

function isGlAdmin(user) {
  return !!user &&
    user.role === "gl_admin";
}


/* =========================================================
   ADMIN USERS
========================================================= */

async function adminUsers(request, env) {

  const meUser =
    await currentUser(request, env);

  if (!isAdmin(meUser)) {
    return json({
      error:
        "Admin huquqi talab qilinadi."
    }, 403);
  }

  if (request.method !== "GET") {
    return json({
      error:
        "Method qo‘llab-quvvatlanmaydi."
    }, 405);
  }

  const rows =
    await env.DB.prepare(`
      SELECT
        users.id,
        users.username,
        users.email,
        users.role,
        users.is_banned,
        users.created_at,

        profiles.first_name,
        profiles.last_name,
        profiles.telegram,
        profiles.phone,
        profiles.steam_id,
        profiles.server_nickname,
        profiles.avatar_url,
        profiles.updated_at,

        user_presence.last_seen

      FROM users

      LEFT JOIN profiles
        ON profiles.user_id = users.id

      LEFT JOIN user_presence
        ON user_presence.user_id = users.id

      ORDER BY users.id DESC
    `)
      .all();

  const now =
    Math.floor(Date.now() / 1000);

  const users =
    (rows.results || []).map(u => ({
      ...u,

      online:
        !u.is_banned &&
        Number(u.last_seen || 0) >=
          now - 90
    }));

  return json({
    users,
    total: users.length
  });
}


/* =========================================================
   ADMIN BAN / UNBAN
========================================================= */

async function adminBan(request, env) {

  const meUser =
    await currentUser(request, env);

  if (!isAdmin(meUser)) {
    return json({
      error:
        "Admin huquqi talab qilinadi."
    }, 403);
  }

  if (request.method !== "POST") {
    return json({
      error:
        "Method qo‘llab-quvvatlanmaydi."
    }, 405);
  }

  const body =
    await request.json().catch(() => null);

  const targetId =
    Number(body?.user_id);

  const banned =
    body?.banned ? 1 : 0;

  if (
    !Number.isInteger(targetId) ||
    targetId <= 0
  ) {
    return json({
      error:
        "Foydalanuvchi ID noto‘g‘ri."
    }, 400);
  }

  if (
    targetId === Number(meUser.id)
  ) {
    return json({
      error:
        "O‘zingizni bloklay olmaysiz."
    }, 400);
  }

  const target =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        role,
        is_banned
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(targetId)
      .first();

  if (!target) {
    return json({
      error:
        "Foydalanuvchi topilmadi."
    }, 404);
  }

  /*
    Oddiy admin faqat userlarni
    bloklay/unblock qila oladi.
  */

  if (
    meUser.role === "admin" &&
    target.role !== "user"
  ) {
    return json({
      error:
        "Admin faqat user foydalanuvchilarni boshqara oladi."
    }, 403);
  }

  /*
    GL Admin akkauntini bloklab bo‘lmaydi.
  */

  if (
    target.role === "gl_admin"
  ) {
    return json({
      error:
        "GL Admin akkauntini bloklash mumkin emas."
    }, 403);
  }

  await env.DB.prepare(`
    UPDATE users
    SET is_banned = ?
    WHERE id = ?
  `)
    .bind(
      banned,
      targetId
    )
    .run();

  if (banned) {

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `)
      .bind(targetId)
      .run();
  }

  return json({
    ok: true,
    user_id: targetId,
    is_banned: !!banned
  });
}


/* =========================================================
   GL ADMIN ROLE
========================================================= */

async function glAdminRole(request, env) {

  const meUser =
    await currentUser(request, env);

  if (!isGlAdmin(meUser)) {
    return json({
      error:
        "Bu amal faqat GL Admin uchun."
    }, 403);
  }

  if (request.method !== "POST") {
    return json({
      error:
        "Method qo‘llab-quvvatlanmaydi."
    }, 405);
  }

  const body =
    await request.json().catch(() => null);

  const targetId =
    Number(body?.user_id);

  const makeAdmin =
    !!body?.make_admin;

  if (
    !Number.isInteger(targetId) ||
    targetId <= 0
  ) {
    return json({
      error:
        "Foydalanuvchi ID noto‘g‘ri."
    }, 400);
  }

  if (
    targetId === Number(meUser.id)
  ) {
    return json({
      error:
        "GL Admin o‘z rolini o‘zgartira olmaydi."
    }, 400);
  }

  const target =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        role,
        is_banned
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(targetId)
      .first();

  if (!target) {
    return json({
      error:
        "Foydalanuvchi topilmadi."
    }, 404);
  }

  if (
    target.role === "gl_admin"
  ) {
    return json({
      error:
        "GL Admin rolini boshqa foydalanuvchiga bera olmaysiz."
    }, 403);
  }

  const newRole =
    makeAdmin
      ? "admin"
      : "user";

  await env.DB.prepare(`
    UPDATE users
    SET role = ?
    WHERE id = ?
  `)
    .bind(
      newRole,
      targetId
    )
    .run();

  return json({
    ok: true,
    user_id: targetId,
    role: newRole
  });
}


/* =========================================================
   ADMIN STATS
========================================================= */

async function adminStats(request, env) {

  const meUser =
    await currentUser(request, env);

  if (!isAdmin(meUser)) {
    return json({
      error:
        "Admin huquqi talab qilinadi."
    }, 403);
  }

  const now =
    Math.floor(Date.now() / 1000);

  const total =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM users
    `)
      .first();

  const users =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM users
      WHERE role = 'user'
    `)
      .first();

  const admins =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM users
      WHERE role = 'admin'
    `)
      .first();

  const banned =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM users
      WHERE is_banned = 1
    `)
      .first();

  const online =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM user_presence
      JOIN users
        ON users.id = user_presence.user_id
      WHERE user_presence.last_seen >= ?
        AND users.is_banned = 0
    `)
      .bind(now - 90)
      .first();

  const messages =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM chat_messages
    `)
      .first();

  return json({
    total_users:
      Number(total?.count || 0),

    users:
      Number(users?.count || 0),

    admins:
      Number(admins?.count || 0),

    banned:
      Number(banned?.count || 0),

    online:
      Number(online?.count || 0),

    chat_messages:
      Number(messages?.count || 0)
  });
}


/* =========================================================
   ADMIN USER DETAILS
========================================================= */

async function adminUserDetails(request, env) {

  const meUser =
    await currentUser(request, env);

  if (!isAdmin(meUser)) {
    return json({
      error:
        "Admin huquqi talab qilinadi."
    }, 403);
  }

  const url =
    new URL(request.url);

  const id =
    Number(
      url.searchParams.get("id")
    );

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {
    return json({
      error:
        "Foydalanuvchi ID noto‘g‘ri."
    }, 400);
  }

  const row =
    await env.DB.prepare(`
      SELECT
        users.id,
        users.username,
        users.email,
        users.role,
        users.is_banned,
        users.created_at,

        profiles.first_name,
        profiles.last_name,
        profiles.telegram,
        profiles.phone,
        profiles.steam_id,
        profiles.server_nickname,
        profiles.avatar_url,
        profiles.updated_at,

        user_presence.last_seen

      FROM users

      LEFT JOIN profiles
        ON profiles.user_id = users.id

      LEFT JOIN user_presence
        ON user_presence.user_id = users.id

      WHERE users.id = ?

      LIMIT 1
    `)
      .bind(id)
      .first();

  if (!row) {
    return json({
      error:
        "Foydalanuvchi topilmadi."
    }, 404);
  }

  /*
    Oddiy admin boshqa admin yoki
    GL Admin ma’lumotlarini ko‘ra olmaydi.
  */

  if (
    meUser.role === "admin" &&
    row.role !== "user"
  ) {
    return json({
      error:
        "Siz faqat user foydalanuvchilar ma’lumotlarini ko‘rishingiz mumkin."
    }, 403);
  }

  return json({
    user: row
  });
}


/* =========================================================
   API ROUTER
========================================================= */

async function api(request, env) {

  const url =
    new URL(request.url);


  /* REGISTER */

  if (
    request.method === "POST" &&
    url.pathname === "/api/register"
  ) {
    return register(
      request,
      env
    );
  }


  /* LOGIN */

  if (
    request.method === "POST" &&
    url.pathname === "/api/login"
  ) {
    return login(
      request,
      env
    );
  }


  /* LOGOUT */

  if (
    request.method === "POST" &&
    url.pathname === "/api/logout"
  ) {
    return logout(
      request,
      env
    );
  }


  /* ME */

  if (
    request.method === "GET" &&
    url.pathname === "/api/me"
  ) {
    return me(
      request,
      env
    );
  }


  /* PRESENCE */

  if (
    request.method === "POST" &&
    url.pathname === "/api/presence"
  ) {
    return presence(
      request,
      env
    );
  }


  /* =======================================================
     CHAT

     GET  = xabarlarni olish
     POST = yangi xabar
     PUT  = xabarni tahrirlash
  ======================================================= */

  if (
    (
      request.method === "GET" ||
      request.method === "POST" ||
      request.method === "PUT"
    ) &&
    url.pathname === "/api/chat"
  ) {
    return chat(
      request,
      env
    );
  }


  /* ONLINE USERS */

  if (
    request.method === "GET" &&
    url.pathname === "/api/online-users"
  ) {
    return onlineUsers(
      request,
      env
    );
  }


  /* ADMIN USERS */

  if (
    request.method === "GET" &&
    url.pathname === "/api/admin/users"
  ) {
    return adminUsers(
      request,
      env
    );
  }


  /* ADMIN USER DETAILS */

  if (
    request.method === "GET" &&
    url.pathname === "/api/admin/user"
  ) {
    return adminUserDetails(
      request,
      env
    );
  }


  /* ADMIN BAN */

  if (
    request.method === "POST" &&
    url.pathname === "/api/admin/ban"
  ) {
    return adminBan(
      request,
      env
    );
  }


  /* ADMIN ROLE */

  if (
    request.method === "POST" &&
    url.pathname === "/api/admin/role"
  ) {
    return glAdminRole(
      request,
      env
    );
  }


  /* ADMIN STATS */

  if (
    request.method === "GET" &&
    url.pathname === "/api/admin/stats"
  ) {
    return adminStats(
      request,
      env
    );
  }


  /* PROFILE */

  if (
    (
      request.method === "GET" ||
      request.method === "PUT"
    ) &&
    url.pathname === "/api/profile"
  ) {
    return profile(
      request,
      env
    );
  }


  return json({
    error:
      "API endpoint topilmadi."
  }, 404);
}


/* =========================================================
   WORKER
========================================================= */

export default {

  async fetch(request, env) {

    const url =
      new URL(request.url);

    if (
      url.pathname.startsWith("/api/")
    ) {
      return api(
        request,
        env
      );
    }

    return env.ASSETS.fetch(
      request
    );
  }
};
