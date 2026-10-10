// Vercel Serverless Function: /api/github/callback
// Dipanggil GitHub setelah user menekan "Authorize". Code ditukar jadi access token
// (butuh Client Secret, jadi hanya berjalan di server). Hasilnya dibungkus token login yang ditandatangani.
//
// Environment variables (Vercel → Settings → Environment Variables):
//   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, SESSION_SECRET, SITE_URL

const { sign } = require("../../lib/auth");

module.exports = async function handler(req, res) {
  const site = (process.env.SITE_URL || "https://yfensagala.vercel.app").replace(/\/$/, "");

  // Data dikirim lewat #hash agar tidak tercatat di log server
  const back = (hash) => {
    res.statusCode = 302;
    res.setHeader("Location", `${site}/#${hash}`);
    res.end();
  };

  try {
    const url = new URL(req.url, site);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") || "";
    const error = url.searchParams.get("error");

    if (error || !code) return back(`autherr=${encodeURIComponent(error || "no_code")}`);

    // 1) Tukar code → access token
    const tr = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      }),
    });
    const { access_token } = await tr.json();
    if (!access_token) return back("autherr=token");

    const gh = {
      Authorization: `Bearer ${access_token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "hasbifx-guestbook",
    };

    // 2) Profil user
    const me = await (await fetch("https://api.github.com/user", { headers: gh })).json();
    if (!me.login) return back("autherr=api");

    // 3) Email (kalau tidak tampil di profil publik)
    let email = me.email;
    if (!email) {
      const list = await (await fetch("https://api.github.com/user/emails", { headers: gh })).json();
      const best = Array.isArray(list)
        ? list.find((x) => x.primary && x.verified) || list.find((x) => x.verified)
        : null;
      email = best ? best.email : `${me.id}+${me.login}@users.noreply.github.com`;
    }

    // 4) Bungkus jadi token login yang ditandatangani, lalu kirim balik ke halaman
    const token = sign({
      p: "github",
      n: me.name || me.login,
      e: email.toLowerCase(),
      a: me.avatar_url || "",
    });
    return back(`auth=${token}&state=${encodeURIComponent(state)}`);
  } catch (err) {
    console.error("GitHub login error:", err);
    return back("autherr=server");
  }
};
