// Vercel Serverless Function: /api/guestbook
// GET  → ambil semua pesan (publik, tanpa email)
// POST → kirim pesan (wajib login; identitas diambil dari token yang ditandatangani server)
//
// Environment variables:
//   SUPABASE_URL              = https://xxxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY = service_role key (RAHASIA, hanya di Vercel)
//   SESSION_SECRET            = string acak panjang
//   ADMIN_EMAIL               = hasbifxtrde@gmail.com

const { verify, readJson } = require("../lib/auth");

const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN = (process.env.ADMIN_EMAIL || "").toLowerCase();
const COOLDOWN_MS = 15000;

const sb = (path, init = {}) =>
  fetch(`${SB_URL}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: SB_KEY,
      Authorization: `Bearer ${SB_KEY}`,
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });

// Hanya field yang aman untuk publik. Email tidak pernah dikirim ke browser.
const shape = (row) => ({
  id: row.id,
  n: row.name,
  a: row.avatar,
  p: row.provider,
  m: row.message,
  r: row.reply_to,
  t: Date.parse(row.created_at),
  dev: !!ADMIN && row.email === ADMIN,
});

module.exports = async function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  const send = (code, obj) => {
    res.statusCode = code;
    res.end(JSON.stringify(obj));
  };

  try {
    if (req.method === "GET") {
      const r = await sb(
        "guestbook?select=id,name,email,avatar,provider,message,reply_to,created_at&order=created_at.asc&limit=300"
      );
      if (!r.ok) return send(500, { error: "db" });
      const rows = await r.json();
      return send(200, rows.map(shape));
    }

    if (req.method === "POST") {
      const user = verify((req.headers.authorization || "").replace(/^Bearer /, ""));
      if (!user) return send(401, { error: "login_required" });

      const { message, reply_to } = await readJson(req);
      const msg = String(message || "").trim();
      if (!msg || msg.length > 280) return send(400, { error: "bad_message" });

      // Anti-spam sederhana: satu akun hanya bisa kirim pesan setiap 15 detik
      const last = await sb(
        `guestbook?select=created_at&email=eq.${encodeURIComponent(user.e)}&order=created_at.desc&limit=1`
      );
      const lastRows = last.ok ? await last.json() : [];
      if (lastRows[0] && Date.now() - Date.parse(lastRows[0].created_at) < COOLDOWN_MS) {
        return send(429, { error: "slow_down" });
      }

      const isAdmin = !!ADMIN && user.e === ADMIN;
      const ins = await sb("guestbook", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          name: isAdmin ? "hasbifx" : String(user.n || "").slice(0, 30),
          email: user.e,
          avatar: user.a || "",
          provider: user.p,
          message: msg,
          reply_to: reply_to ? Number(reply_to) : null,
        }),
      });
      if (!ins.ok) return send(400, { error: "insert_failed" });

      const [row] = await ins.json();
      return send(201, shape(row));
    }

    return send(405, { error: "method_not_allowed" });
  } catch (err) {
    console.error("Guestbook error:", err);
    return send(500, { error: "server" });
  }
};
