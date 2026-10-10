// lib/auth.js — helper bersama untuk token login dan membaca body JSON.
// Token = base64url(JSON data user + exp) + "." + HMAC-SHA256 (pakai SESSION_SECRET).
// Hanya server yang bisa membuat token yang valid.

const crypto = require("crypto");

const WEEK = 7 * 24 * 60 * 60 * 1000;

function sign(user) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET belum diisi di Vercel");
  const body = Buffer.from(JSON.stringify({ ...user, exp: Date.now() + WEEK }), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verify(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || typeof token !== "string") return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;

  const expected = Buffer.from(crypto.createHmac("sha256", secret).update(body).digest("base64url"));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

  let user;
  try {
    user = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch (_) {
    return null;
  }
  if (!user.exp || user.exp < Date.now()) return null;
  return user;
}

function readJson(req) {
  if (req.body) return Promise.resolve(typeof req.body === "string" ? JSON.parse(req.body) : req.body);
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 20000) {
        reject(new Error("body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

module.exports = { sign, verify, readJson };
