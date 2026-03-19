import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

const TURNSTILE_SECRET = "0x4AAAAAACs8dTjOU5UcntgtIKPw4lJznNg";
const SESSION_EXPIRY = 259200; // 72 Jam (3 Hari)

async function verifyTurnstile(token, ip) {
  if (!token) return false;
  const formData = new FormData(); formData.append('secret', TURNSTILE_SECRET); formData.append('response', token); formData.append('remoteip', ip || '');
  try { const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: formData }); return (await res.json()).success; } catch (e) { return false; }
}

// Fungsi Kirim Email Cerdas (Menangani OTP dan Magic Links)
async function sendMail(env, toEmail, token, purpose) {
  if (!env.RESEND_API_KEY) return { success: false, reason: "NO_API_KEY" };
  const host = "https://sso.orlandmanagement.com";
  let subject, html;

  if (purpose === 'activation') {
      subject = "Aktivasi Akun Orland Management";
      html = `<div style="font-family:sans-serif; padding:20px;"><h2>Satu Langkah Lagi!</h2><p>Klik tombol di bawah ini untuk mengaktifkan akun Anda:</p><br><a href="${host}/?activation_token=${token}" style="background-color:#6b8aed; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold;">Aktifkan Akun Saya</a><br><br><p>Atau copy link berikut: <br><span style="color:#888;">${host}/?activation_token=${token}</span></p></div>`;
  } else if (purpose === 'reset') {
      subject = "Reset Password Orland Management";
      html = `<div style="font-family:sans-serif; padding:20px;"><h2>Reset Password</h2><p>Kami menerima permintaan untuk mereset password Anda. Link ini berlaku selama 30 Menit.</p><br><a href="${host}/?reset_token=${token}" style="background-color:#ef4444; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold;">Reset Password Sekarang</a></div>`;
  } else {
      subject = "Kode OTP Orland Management";
      html = `<div style="font-family:sans-serif; padding:20px;"><h2>Verifikasi Keamanan</h2><p>Berikut kode OTP Anda (Berlaku 3 Menit):</p><h1 style="letter-spacing:5px; color:#6b8aed;">${token}</h1></div>`;
  }

  try {
    const res = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: 'Orland Management <no-reply@orlandmanagement.com>', to: toEmail, subject, html }) });
    if (!res.ok) return { success: false }; return { success: true };
  } catch (e) { return { success: false }; }
}

function getPortalUrl(role) { return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com'; }

export async function onRequestGet({ request, env, params }) {
  if (params.action === "me") {
    const cookies = parseCookies(request);
    if (!cookies.sid) return jsonError("Tidak ada sesi.", 401);
    const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, Math.floor(Date.now() / 1000)).first();
    if (!session) return jsonError("Sesi kadaluarsa.", 401);
    const user = await env.DB.prepare("SELECT id, full_name, email, role FROM users WHERE id=?").bind(session.user_id).first();
    return user ? jsonOk({ user }) : jsonError("User tidak ada.", 404);
  }
  return jsonError("GET Invalid", 404);
}

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

    // --- RATE LIMITING KETAT (5x per Menit) ---
    try {
      await env.DB.prepare("DELETE FROM ip_rate_limit WHERE expires_at < ?").bind(now).run();
      const rl = await env.DB.prepare("SELECT count FROM ip_rate_limit WHERE ip = ?").bind(clientIp).first();
      if (rl && rl.count >= 5) return jsonError("Terlalu banyak percobaan. IP diblokir 1 menit.", 429);
      await env.DB.prepare("INSERT INTO ip_rate_limit (ip, count, expires_at) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET count = count + 1").bind(clientIp, now + 60).run();
    } catch (e) {}

    const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(id, id).first();

    // === GOOGLE ONE TAP ===
    if (action === "google-login") {
      const tokenRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${body.credential}`);
      const gData = await tokenRes.json();
      if (!tokenRes.ok || !gData.email) return jsonError("Autentikasi Google Gagal.");
      let user = await findUser(gData.email);
      if (!user) return jsonOk({ is_new: true, temp_token: btoa(JSON.stringify({ email: gData.email, name: gData.name })) });
      if(user.status !== 'active') await env.DB.prepare("UPDATE users SET status='active' WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
      return jsonOk({ message: "Login Google Sukses!", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    if (action === "social-complete") {
      let decoded; try { decoded = JSON.parse(atob(body.temp_token)); } catch(e) { return jsonError("Tiket tidak valid."); }
      const newUserId = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO users (id, full_name, email, role, status, created_at) VALUES (?,?,?,?,'active',?)").bind(newUserId, decoded.name, decoded.email, body.role, now).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, newUserId, body.role, now, now + SESSION_EXPIRY).run();
      return jsonOk({ message: "Pendaftaran Sukses!", redirect_url: getPortalUrl(body.role) }, makeSessionCookie(sid));
    }

    if (["login-password", "register"].includes(action)) {
      const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
      if (!isHuman) return jsonError("Validasi keamanan gagal (Bot Terdeteksi).", 403);
    }

    // === REGISTER (MAGIC LINK AKTIVASI) ===
    if (action === "register") {
      const existingUser = await findUser(body.email);
      if (existingUser) return jsonError("Email/No HP sudah terdaftar.");

      const hashedPw = await hashData(body.password);
      await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
        .bind(crypto.randomUUID(), body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
      
      const tokenUUID = crypto.randomUUID() + crypto.randomUUID(); // Token panjang
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), body.email, tokenUUID, 'activation', now + 86400).run(); // 24 Jam
      
      const mail = await sendMail(env, body.email, tokenUUID, 'activation');
      return jsonOk({ message: mail.success ? "Link Aktivasi telah dikirim ke Email Anda." : "Email gangguan. Hubungi Admin.", sim_token: mail.success ? undefined : tokenUUID });
    }

    // === VERIFY MAGIC LINK AKTIVASI ===
    if (action === "verify-activation") {
      const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='activation' AND expires_at > ?").bind(body.token, now).first();
      if(!tokenRow) return jsonError("Link tidak valid atau sudah kadaluarsa.");
      
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
      await env.DB.prepare("UPDATE users SET status='active' WHERE email=?").bind(tokenRow.identifier).run();
      
      const user = await findUser(tokenRow.identifier);
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
      return jsonOk({ message: "Aktivasi Berhasil", role: user.role, redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    // === LUPA PASSWORD (MAGIC LINK RESET) ===
    if (action === "request-reset") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      
      const tokenUUID = crypto.randomUUID() + crypto.randomUUID();
      await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=? AND purpose='reset'").bind(user.email).run();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, tokenUUID, 'reset', now + 1800).run(); // 30 Menit
      
      const mail = await sendMail(env, user.email, tokenUUID, 'reset');
      return jsonOk({ message: mail.success ? "Link Reset Password telah dikirim ke Email Anda." : "Gagal kirim email." });
    }

    // === RESET PASSWORD BARU ===
    if (action === "reset-password") {
      const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='reset' AND expires_at > ?").bind(body.token, now).first();
      if(!tokenRow) return jsonError("Link Reset tidak valid atau kadaluarsa.");
      
      const hashedPw = await hashData(body.new_password);
      await env.DB.prepare("UPDATE users SET password_hash=?, fail_count=0, locked_until=NULL WHERE email=?").bind(hashedPw, tokenRow.identifier).run();
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
      return jsonOk({ message: "Password berhasil diubah. Silakan Login." });
    }

    // === LOGIN REGULER (Email + Pass) ===
    if (action === "login-password") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      if (user.locked_until && user.locked_until > now) return jsonError("Akun terkunci. Coba lagi nanti.", 429);
      
      const hashInput = await hashData(body.password);
      if (user.password_hash !== hashInput) {
        const fails = (user.fail_count || 0) + 1;
        if (fails >= 5) {
          await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + 900, user.id).run(); // Lock 15 Menit
          return jsonError("Gagal 5x. Akun dikunci 15 Menit.", 429);
        }
        await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
        return jsonError("Kredensial salah.", 401);
      }

      if(user.status !== 'active') return jsonError("Akun belum diaktifkan. Silakan cek email Anda.", 403);

      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
      return jsonOk({ redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    // === LOGIN PIN FLOW ===
    if (action === "check-pin") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      return jsonOk({ has_pin: user.pin_hash ? true : false, email: user.email });
    }

    if (action === "login-pin") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      if (user.locked_until && user.locked_until > now) return jsonError("Akses diblokir sementara.", 429);
      
      const hashInput = await hashData(body.pin);
      if (user.pin_hash !== hashInput) {
        const fails = (user.fail_count || 0) + 1;
        if (fails >= 3) {
          await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + 900, user.id).run();
          return jsonError("PIN Salah 3x. Akun dikunci 15 menit. Silakan login via Password nanti.", 429);
        }
        await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
        return jsonError(`PIN Salah. Sisa percobaan: ${3 - fails}`, 401);
      }

      if(user.status !== 'active') return jsonError("Akun belum diverifikasi.", 403);
      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
      return jsonOk({ redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    // === REQUEST OTP (Untuk Login/Setup PIN) ===
    if (action === "request-otp") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=?").bind(user.email).run();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, otp, body.purpose, now + 180).run();
      const mail = await sendMail(env, user.email, otp, body.purpose);
      return jsonOk({ message: "Kode OTP terkirim" });
    }

    // === LOGIN OTP / SETUP PIN OTP ===
    if (action === "verify-otp" || action === "login-otp" || action === "setup-pin") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP salah atau expired.");
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      
      const user = await findUser(body.identifier);
      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      
      if(action === "setup-pin") {
          const hashedPin = await hashData(body.new_pin);
          await env.DB.prepare("UPDATE users SET pin_hash=? WHERE id=?").bind(hashedPin, user.id).run();
      }

      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
      return jsonOk({ message: "Akses Diberikan", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    return jsonError("Endpoint invalid", 404);
  } catch(e) { return jsonError("Server Error", 500); }
}
