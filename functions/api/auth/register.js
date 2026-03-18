import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const now = Math.floor(Date.now() / 1000);
  const id = crypto.randomUUID();
  const hashedPw = await hashData(body.password);
  
  try {
    await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, social_provider, social_id, status, created_at) VALUES (?,?,?,?,?,?,?,?,'pending',?)")
      .bind(id, body.fullName, body.email, body.phone, body.role, hashedPw, body.provider||null, body.social_id||null, now).run();
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), body.email, otp, 'register', now + 300).run();
      
    // Di production riil, kirim OTP via Email/WA API disini.
    return jsonOk({ message: "Registrasi sukses. OTP terkirim.", sim_otp: otp });
  } catch(e) { return jsonError("Gagal: Email/No HP sudah digunakan."); }
}
