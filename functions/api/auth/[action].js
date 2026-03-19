import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

const TURNSTILE_SECRET = "0x4AAAAAACs8dTjOU5UcntgtIKPw4lJznNg";

async function verifyTurnstile(token, ip) {
  if (!token) return false;
  const formData = new FormData(); formData.append('secret', TURNSTILE_SECRET); formData.append('response', token); formData.append('remoteip', ip || '');
  try { const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: formData }); return (await res.json()).success; } catch (e) { return false; }
}

async function sendOtpEmail(env, toEmail, otpCode, purpose) {
  if (!env.RESEND_API_KEY) return { success: false, reason: "NO_API_KEY" };
  let subject = purpose === 'register' ? "Aktivasi Akun Orland Management" : "Kode OTP Login Anda";
  let html = `<div style="font-family:sans-serif; padding:20px;"><h2>Orland Management SSO</h2><p>Berikut kode OTP Anda:</p><h1 style="letter-spacing:5px; color:#6b8aed;">${otpCode}</h1><p>Kode ini berlaku 3 menit.</p></div>`;
  try {
    const res = await fetch('https://api.resend.com/emails', { 
        method: 'POST', 
        headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ from: 'Orland Management <no-reply@orlandmanagement.com>', to: toEmail, subject, html }) 
    });
    if (!res.ok) return { success: false, reason: "RESEND_REJECTED" };
    return { success: true };
  } catch (e) { return { success: false, reason: "FETCH_ERROR" }; }
}

function getPortalUrl(role) { return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com'; }

// ENDPOINT GET (Untuk cek Sesi saat Halaman Dimuat)
export async function onRequestGet({ request, env, params }) {
  if (params.action === "me") {
    const cookies = parseCookies(request);
    if (!cookies.sid) return jsonError("Tidak ada sesi.", 401);
    const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, Math.floor(Date.now() / 1000)).first();
    if (!session) return jsonError("Sesi kadaluarsa.", 401);
    const user = await env.DB.prepare("SELECT id, full_name, email, role FROM users WHERE id=?").bind(session.user_id).first();
    if (!user) return jsonError("User tidak ada.", 404);
    return jsonOk({ user });
  }
  return jsonError("GET Invalid", 404);
}

// ENDPOINT POST
export async function onRequestPost({ request, env, params }) {
  try {
    const action = params.action;
    if (action === "logout") {
        const cookies = parseCookies(request);
        if (cookies.sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookies.sid).run();
        return jsonOk({ message: "Logout Sukses" }, clearSessionCookie());
    }

    const body = await request.json().catch(() => ({}));
    const now = Math.floor(Date.now() / 1000);
    const clientIp = request.headers.get("cf-connecting-ip") || "unknown_ip";

    try {
      await env.DB.prepare("DELETE FROM ip_rate_limit WHERE expires_at < ?").bind(now).run();
      const rl = await env.DB.prepare("SELECT count FROM ip_rate_limit WHERE ip = ?").bind(clientIp).first();
      if (rl && rl.count >= 20) return jsonError("IP diblokir sementara.", 429);
      await env.DB.prepare("INSERT INTO ip_rate_limit (ip, count, expires_at) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET count = count + 1").bind(clientIp, now + 60).run();
    } catch (e) {}

    const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(id, id).first();

    if (action === "google-login") {
      const tokenRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${body.credential}`);
      const gData = await tokenRes.json();
      if (!tokenRes.ok || !gData.email) return jsonError("Autentikasi Google Gagal.");

      let user = await findUser(gData.email);
      if (!user) return jsonOk({ is_new: true, temp_token: btoa(JSON.stringify({ email: gData.email, name: gData.name })) });

      if(user.status !== 'active') await env.DB.prepare("UPDATE users SET status='active' WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      return jsonOk({ message: "Login Google Sukses!", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    if (action === "social-complete") {
      let decoded; try { decoded = JSON.parse(atob(body.temp_token)); } catch(e) { return jsonError("Tiket tidak valid."); }
      const newUserId = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO users (id, full_name, email, role, status, created_at) VALUES (?,?,?,?,'active',?)").bind(newUserId, decoded.name, decoded.email, body.role, now).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, newUserId, body.role, now, now + 604800).run();
      return jsonOk({ message: "Pendaftaran Sukses!", redirect_url: getPortalUrl(body.role) }, makeSessionCookie(sid));
    }

    if (["login-password", "login-pin", "register"].includes(action)) {
      const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
      if (!isHuman) return jsonError("Validasi keamanan gagal (Bot Terdeteksi).", 403);
    }

    if (action === "login-password" || action === "login-pin") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      if (user.locked_until && user.locked_until > now) return jsonError("Akun terkunci sementara.", 429);
      
      const hashInput = await hashData(body.password || body.pin);
      if ((action === "login-password" && user.password_hash !== hashInput) || (action === "login-pin" && user.pin_hash !== hashInput)) {
        const fails = (user.fail_count || 0) + 1;
        if (fails >= 5) {
          await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + 900, user.id).run();
          return jsonError("Terlalu banyak percobaan.", 429);
        }
        await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
        return jsonError("Kredensial salah.", 401);
      }

      if(user.status !== 'active') {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=?").bind(user.email).run();
        await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, otp, 'register', now + 180).run(); // 3 MENIT
        const mail = await sendOtpEmail(env, user.email, otp, 'register');
        return jsonOk({ needs_activation: true, email: user.email, message: mail.success ? "Akun belum aktif. OTP aktivasi baru dikirim." : "Akun belum aktif. Email gangguan.", sim_otp: mail.success ? undefined : otp });
      }

      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      return jsonOk({ redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    if (action === "register") {
      // 1. Cek User (Pisahkan dari try-catch agar error Resend tidak terbaca 'Email Terdaftar')
      const existingUser = await findUser(body.email);
      if (existingUser) return jsonError("Email/No HP sudah terdaftar.");

      const hashedPw = await hashData(body.password);
      await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
        .bind(crypto.randomUUID(), body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
      
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), body.email, otp, 'register', now + 180).run(); // 3 MENIT
      
      const mail = await sendOtpEmail(env, body.email, otp, 'register');
      return jsonOk({ message: mail.success ? "Registrasi sukses. Cek Email Anda." : "Registrasi sukses. (Email gagal terkirim)", sim_otp: mail.success ? undefined : otp });
    }

    if (action === "request-otp") {
      const user = await findUser(body.identifier);
      if(!user && body.purpose !== 'register') return jsonError("Akun tidak ditemukan.", 404);
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=?").bind(body.identifier).run();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), body.identifier, otp, body.purpose, now + 180).run(); // 3 MENIT
      
      let emailStatus = { success: false };
      if(body.identifier.includes('@')) emailStatus = await sendOtpEmail(env, body.identifier, otp, body.purpose);
      if (!emailStatus.success && body.identifier.includes('@')) return jsonOk({ message: "Sistem Email bermasalah.", sim_otp: otp });
      return jsonOk({ message: "Kode OTP terkirim" });
    }

    if (action === "verify-otp" || action === "login-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP salah atau kadaluarsa (Lebih dari 3 Menit).");
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      
      if(action === "login-otp") {
        const user = await findUser(body.identifier);
        await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
        const sid = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
        return jsonOk({ redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
      } else {
        if(otpRow.purpose === 'register') await env.DB.prepare("UPDATE users SET status='active' WHERE email=? OR phone=?").bind(body.identifier, body.identifier).run();
        return jsonOk({ message: "Verifikasi Berhasil" });
      }
    }

    if (action === "set-pin") {
      const hashedPin = await hashData(body.pin);
      const user = await findUser(body.identifier);
      await env.DB.prepare("UPDATE users SET pin_hash=? WHERE email=? OR phone=?").bind(hashedPin, body.identifier, body.identifier).run();
      return jsonOk({ redirect_url: user ? getPortalUrl(user.role) : "https://dashboard.orlandmanagement.com" });
    }

    return jsonError("Endpoint invalid", 404);
  } catch(e) { return jsonError("Server Error", 500); }
}
