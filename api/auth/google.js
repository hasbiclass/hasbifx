// Vercel Serverless Function: /api/auth/google
// Dipanggil dari index.html setelah user login lewat popup Google.
// Access token dicek ke Google di server, lalu dibungkus token login yang ditandatangani.
//
// Environment variables: SESSION_SECRET

const { sign, readJson } = require("../../lib/auth");

module.exports = async function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  const send = (code, obj) => {
    res.statusCode = code;
    res.end(JSON.stringify(obj));
  };

  if (req.method !== "POST") return send(405, { error: "method_not_allowed" });

  try {
    const { access_token } = await readJson(req);
    if (!access_token) return send(400, { error: "no_token" });

    const r = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const u = await r.json();
    if (!r.ok || !u.email || !u.email_verified) return send(401, { error: "google_unverified" });

    const token = sign({
      p: "google",
      n: u.name || u.email.split("@")[0],
      e: u.email.toLowerCase(),
      a: u.picture || "",
    });
    return send(200, { token });
  } catch (err) {
    console.error("Google login error:", err);
    return send(500, { error: "server" });
  }
};
