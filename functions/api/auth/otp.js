import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const now = Math.floor(Date.now() / 1000);

  // Jika Request OTP (Forgot/Login via OTP)
  if(body.action === 'request') {
     const otp = Math.floor(100000 + Math.random() * 900000).toString();
     await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
        .bind(crypto.randomUUID(), body.identifier, otp, body.purpose, now + 300).run();
     return jsonOk({ message: "OTP Terkirim", sim_otp: otp });
  }

  // Jika Verify OTP
  if(body.action === 'verify') {
     const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
     if(!otpRow) return jsonError("OTP tidak valid atau kadaluarsa.");
     await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
     
     if(otpRow.purpose === 'register') await env.DB.prepare("UPDATE users SET status='active' WHERE email=? OR phone=?").bind(body.identifier, body.identifier).run();
     return jsonOk({ message: "Verifikasi sukses", purpose: otpRow.purpose });
  }

  // Jika Set PIN (Setelah OTP Reset / Aktivasi)
  if(body.action === 'set_pin') {
     const hashedPin = await hashData(body.pin);
     await env.DB.prepare("UPDATE users SET pin_hash=? WHERE email=? OR phone=?").bind(hashedPin, body.identifier, body.identifier).run();
     return jsonOk({ message: "PIN berhasil disimpan." });
  }

  return jsonError("Action tidak dikenal.");
}
