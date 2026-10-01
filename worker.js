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
      users.email
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
    return json({ error: "Noto‘g‘ri JSON." }, 400);
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
      password_hash
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
        email: user.email
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
          email: user.email
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


  /* GET */

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


  /* PUT */

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
        .slice(0, 500)
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
   API ROUTER
========================================================= */

async function api(request, env) {

  const url = new URL(request.url);

  if (
    request.method === "POST" &&
    url.pathname === "/api/register"
  ) {
    return register(request, env);
  }

  if (
    request.method === "POST" &&
    url.pathname === "/api/login"
  ) {
    return login(request, env);
  }

  if (
    request.method === "POST" &&
    url.pathname === "/api/logout"
  ) {
    return logout(request, env);
  }

  if (
    request.method === "GET" &&
    url.pathname === "/api/me"
  ) {
    return me(request, env);
  }

  if (
    (
      request.method === "GET" ||
      request.method === "PUT"
    ) &&
    url.pathname === "/api/profile"
  ) {
    return profile(request, env);
  }

  return json({
    error: "API endpoint topilmadi."
  }, 404);
}


/* =========================================================
   WORKER
========================================================= */

export default {

  async fetch(request, env) {

    const url = new URL(request.url);

    if (
      url.pathname.startsWith("/api/")
    ) {
      return api(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};
