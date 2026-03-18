import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie } from "../../_lib/cookies.js";

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const user = await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(body.identifier, body.identifier).first();
  
  if(!user) return jsonError("Akun tidak ditemukan.", 404);
  if(user.status !== 'active') return jsonError("Akun belum diverifikasi.", 403);

  const hashInput = await hashData(body.password || body.pin);
  if(body.password && user.password_hash !== hashInput) return jsonError("Password salah.", 401);
  if(body.pin && user.pin_hash !== hashInput) return jsonError("PIN salah.", 401);

  // --- LOGIN SUKSES: BUAT SESSION & COOKIE ---
  const sid = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const expires = now + (7 * 24 * 60 * 60); // Sesi aktif 7 Hari

  await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)")
    .bind(sid, user.id, user.role, now, expires).run();

  const cookieStr = makeSessionCookie(sid);

  return jsonOk({ message: "Login Sukses", role: user.role, redirect_url: "https://dashboard.orlandmanagement.com" }, cookieStr);
}
