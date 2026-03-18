import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

export async function onRequestPost({ request, env, params }) {
  try {
    const action = params.action;
    const body = await request.json().catch(() => ({}));
    const now = Math.floor(Date.now() / 1000);
    const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(id, id).first();

    // 1. LOGIN (PASSWORD & PIN) + ANTI BRUTE-FORCE
    if (action === "login-password" || action === "login-pin") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      if (user.locked_until && user.locked_until > now) return jsonError(`Akun terkunci. Coba lagi nanti.`, 429);
      if(user.status !== 'active') return jsonError("Akun belum diverifikasi.", 403);

      const hashInput = await hashData(body.password || body.pin);
      if ((action === "login-password" && user.password_hash !== hashInput) || (action === "login-pin" && user.pin_hash !== hashInput)) {
        const fails = (user.fail_count || 0) + 1;
        if (fails >= 5) {
          await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + 900, user.id).run();
          return jsonError("Terlalu banyak percobaan. Akun dikunci 15 menit.", 429);
        }
        await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
        return jsonError("Kredensial salah.", 401);
      }

      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      
      return jsonOk({ message: "Login Sukses", role: user.role, redirect_url: "https://dashboard.orlandmanagement.com" }, makeSessionCookie(sid));
    }

    // 2. LOGOUT
    if (action === "logout") {
      const cookies = parseCookies(request);
      if (cookies.sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookies.sid).run();
      return jsonOk({ message: "Logout Sukses" }, clearSessionCookie());
    }

    // 3. REGISTER
    if (action === "register") {
      const hashedPw = await hashData(body.password);
      const id = crypto.randomUUID();
      try {
        await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
          .bind(id, body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
          .bind(crypto.randomUUID(), body.email, otp, 'register', now + 300).run();
          
        return jsonOk({ message: "Registrasi sukses.", sim_otp: otp });
      } catch(e) { return jsonError("Email atau No HP sudah terdaftar."); }
    }

    // 4. VERIFY OTP
    if (action === "verify-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP tidak valid atau kadaluarsa.");
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      
      if(otpRow.purpose === 'register') await env.DB.prepare("UPDATE users SET status='active' WHERE email=? OR phone=?").bind(body.identifier, body.identifier).run();
      return jsonOk({ message: "Verifikasi berhasil.", purpose: otpRow.purpose });
    }

    // 5. SET PIN
    if (action === "set-pin") {
      const hashedPin = await hashData(body.pin);
      await env.DB.prepare("UPDATE users SET pin_hash=? WHERE email=? OR phone=?").bind(hashedPin, body.identifier, body.identifier).run();
      return jsonOk({ message: "PIN berhasil disimpan." });
    }

    // 6. REQUEST OTP (Forgot / Login OTP)
    if (action === "request-otp") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak terdaftar.");
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
        .bind(crypto.randomUUID(), body.identifier, otp, body.purpose || 'login', now + 300).run();
      return jsonOk({ message: "OTP Terkirim.", sim_otp: otp });
    }

    // 7. SOCIAL CHECK & REGISTER
    if (action === "social-check") {
      const user = await env.DB.prepare("SELECT * FROM users WHERE social_id=?").bind(body.social_id).first();
      if(user) return jsonOk({ exists: true, message: "Login Social Sukses" });
      return jsonOk({ exists: false, data: { name: body.name, email: body.email } });
    }
    
    if (action === "social-register") {
       const hashedPw = await hashData(body.password);
       const id = crypto.randomUUID();
       try {
         await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, social_provider, social_id, status, created_at) VALUES (?,?,?,?,?,?,?,?,'active',?)")
           .bind(id, body.fullName, body.email, body.phone, body.role, hashedPw, body.provider, body.social_id, now).run();
         return jsonOk({ message: "Akun Sosial berhasil dibuat. Silakan set PIN." });
       } catch(e) { return jsonError("Gagal daftar, email/HP mungkin sudah ada."); }
    }

    return jsonError("Endpoint tidak valid.", 404);
  } catch(e) { return jsonError("Server Error", 500); }
}

export async function onRequestGet({ request, env, params }) {
  const action = params.action;
  const now = Math.floor(Date.now() / 1000);

  // ENDPOINT "/me" (Verifikasi Sesi Lintas App)
  if (action === "me") {
    const cookies = parseCookies(request);
    if (!cookies.sid) return jsonError("Tidak ada sesi aktif.", 401);
    const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, now).first();
    if (!session) return jsonError("Sesi kadaluarsa.", 401);
    const user = await env.DB.prepare("SELECT id, full_name, email, phone, role FROM users WHERE id=?").bind(session.user_id).first();
    if (!user) return jsonError("User tidak ditemukan.", 404);
    
    return jsonOk({ user });
  }

  return jsonError("Endpoint GET tidak valid.", 404);
}
