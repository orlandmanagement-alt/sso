import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

const TURNSTILE_SECRET = "0x4AAAAAACs8dTjOU5UcntgtIKPw4lJznNg";

async function verifyTurnstile(token, ip) {
  if (!token) return false;
  const formData = new FormData();
  formData.append('secret', TURNSTILE_SECRET);
  formData.append('response', token);
  formData.append('remoteip', ip || '');
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: formData });
    const data = await res.json();
    return data.success;
  } catch (e) { return false; }
}

export async function onRequestPost({ request, env, params }) {
  try {
    const action = params.action;
    const body = await request.json().catch(() => ({}));
    const now = Math.floor(Date.now() / 1000);
    const clientIp = request.headers.get("cf-connecting-ip") || "unknown_ip";

    // --- WAF MINI ---
    try {
      await env.DB.prepare("DELETE FROM ip_rate_limit WHERE expires_at < ?").bind(now).run();
      const rl = await env.DB.prepare("SELECT count FROM ip_rate_limit WHERE ip = ?").bind(clientIp).first();
      if (rl && rl.count >= 20) return jsonError("Terlalu banyak request. IP diblokir 1 menit.", 429);
      await env.DB.prepare("INSERT INTO ip_rate_limit (ip, count, expires_at) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET count = count + 1").bind(clientIp, now + 60).run();
    } catch (e) { console.log("WAF Bypass"); }

    // --- TURNSTILE ---
    if (["login-password", "login-pin", "register", "login-otp", "social-register"].includes(action)) {
      const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
      if (!isHuman) return jsonError("Validasi keamanan gagal. Terdeteksi sebagai Bot.", 403);
    }

    const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(id, id).first();

    // 1. LOGIN PASSWORD & PIN
    if (action === "login-password" || action === "login-pin") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      if (user.locked_until && user.locked_until > now) return jsonError("Akun terkunci sementara.", 429);
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
      return jsonOk({ message: "Login Sukses", role: user.role }, makeSessionCookie(sid));
    }

    // 2. REQUEST OTP (Login OTP / Forgot Password)
    if (action === "request-otp") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=?").bind(body.identifier).run();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
        .bind(crypto.randomUUID(), body.identifier, otp, body.purpose || 'login', now + 300).run();
      
      return jsonOk({ message: "Kode / Tautan terkirim", sim_otp: otp }); // sim_otp dikembalikan untuk kemudahan simulasi
    }

    // 3. LOGIN VIA OTP
    if (action === "login-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose='login' AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP tidak valid atau kadaluarsa.");
      
      const user = await findUser(body.identifier);
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      return jsonOk({ message: "Login Sukses", role: user.role }, makeSessionCookie(sid));
    }

    // 4. REGISTER
    if (action === "register") {
      const hashedPw = await hashData(body.password);
      const id = crypto.randomUUID();
      try {
        await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
          .bind(id, body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
          .bind(crypto.randomUUID(), body.email, otp, 'register', now + 300).run();
          
        return jsonOk({ message: "Registrasi sukses. Silakan buka tautan di email.", sim_otp: otp });
      } catch(e) { return jsonError("Email atau No HP sudah terdaftar."); }
    }

    // 5. VERIFY OTP (Untuk Aktivasi Register)
    if (action === "verify-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP / Link tidak valid.");
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      if(otpRow.purpose === 'register') await env.DB.prepare("UPDATE users SET status='active' WHERE email=? OR phone=?").bind(body.identifier, body.identifier).run();
      return jsonOk({ message: "Akun aktif." });
    }

    // 6. SET PIN
    if (action === "set-pin") {
      const hashedPin = await hashData(body.pin);
      await env.DB.prepare("UPDATE users SET pin_hash=? WHERE email=? OR phone=?").bind(hashedPin, body.identifier, body.identifier).run();
      return jsonOk({ message: "PIN berhasil disimpan." });
    }

    // 7. SOCIAL CHECK & REGISTER SIMULATION
    if (action === "social-check") {
      // Simulasi: Selalu anggap akun belum ada untuk demo UI Social Register
      return jsonOk({ exists: false, data: { name: "Pengguna " + body.provider, email: "user@" + body.provider.toLowerCase() + ".com" } });
    }
    
    if (action === "social-register") {
      const hashedPw = await hashData(body.password);
      try {
        await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'active',?)")
          .bind(crypto.randomUUID(), body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
        return jsonOk({ message: "Registrasi Sosial sukses. Silakan buat PIN." });
      } catch(e) { return jsonError("Gagal mendaftar."); }
    }

    if (action === "logout") {
      const cookies = parseCookies(request);
      if (cookies.sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookies.sid).run();
      return jsonOk({ message: "Logout Sukses" }, clearSessionCookie());
    }

    return jsonError("Endpoint tidak valid.", 404);
  } catch(e) { return jsonError("Server Error", 500); }
}

export async function onRequestGet({ request, env, params }) {
  if (params.action === "me") {
    const cookies = parseCookies(request);
    if (!cookies.sid) return jsonError("Tidak ada sesi aktif.", 401);
    const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, Math.floor(Date.now() / 1000)).first();
    if (!session) return jsonError("Sesi kadaluarsa.", 401);
    const user = await env.DB.prepare("SELECT id, full_name, email, phone, role FROM users WHERE id=?").bind(session.user_id).first();
    return user ? jsonOk({ user }) : jsonError("User tidak ditemukan.", 404);
  }
  return jsonError("Endpoint GET tidak valid.", 404);
}
