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
  if (!env.RESEND_API_KEY) return;
  let subject = purpose === 'register' ? "Aktivasi Akun Orland Management" : "Kode OTP Login Anda";
  let html = `<div style="font-family:sans-serif; padding:20px;"><h2>Orland Management SSO</h2><p>Berikut adalah 6 digit kode OTP Anda:</p><h1 style="letter-spacing:5px; color:#5b83e8;">${otpCode}</h1><p>Kode ini berlaku 5 menit.</p></div>`;
  await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: 'Orland Management <no-reply@orlandmanagement.com>', to: toEmail, subject, html }) }).catch(() => {});
}

// Helper penentu URL Portal berdasarkan Role
function getPortalUrl(role) {
  return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com';
}

export async function onRequestPost({ request, env, params }) {
  try {
    const action = params.action;
    const body = await request.json().catch(() => ({}));
    const now = Math.floor(Date.now() / 1000);
    const clientIp = request.headers.get("cf-connecting-ip") || "unknown_ip";

    const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(id, id).first();

    // === GOOGLE ONE TAP (1-CLICK LOGIN/REGISTER) ===
    if (action === "google-login") {
      const tokenRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${body.credential}`);
      const gData = await tokenRes.json();
      if (!tokenRes.ok || !gData.email) return jsonError("Autentikasi Google Gagal.");

      let user = await findUser(gData.email);
      let isNewUser = false;
      
      // Jika user belum ada, buat langsung ke DB tanpa password
      if (!user) {
        const newId = crypto.randomUUID();
        const assignedRole = body.role || 'talent'; // Role diambil dari UI Frontend
        await env.DB.prepare("INSERT INTO users (id, full_name, email, role, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)")
          .bind(newId, gData.name, gData.email, assignedRole, now).run();
        user = { id: newId, role: assignedRole };
        isNewUser = true;
      } else if (user.status !== 'active') {
        // Jika user ada tapi belum verif OTP, otomatis diaktifkan karena Google terpercaya
        await env.DB.prepare("UPDATE users SET status='active' WHERE id=?").bind(user.id).run();
      }

      // Buat sesi login
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      
      return jsonOk({ 
        message: isNewUser ? "Pendaftaran Google Sukses!" : "Login Google Sukses!", 
        role: user.role, 
        redirect_url: getPortalUrl(user.role) 
      }, makeSessionCookie(sid));
    }

    // === WAF & TURNSTILE ===
    if (["login-password", "login-pin", "register", "login-otp"].includes(action)) {
      const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
      if (!isHuman) return jsonError("Validasi keamanan gagal. Terdeteksi sebagai Bot.", 403);
    }

    // === NORMAL LOGIN ===
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
          return jsonError("Terlalu banyak percobaan.", 429);
        }
        await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
        return jsonError("Kredensial salah.", 401);
      }
      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      return jsonOk({ message: "Login Sukses", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    // === NORMAL REGISTER ===
    if (action === "register") {
      const hashedPw = await hashData(body.password);
      try {
        await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
          .bind(crypto.randomUUID(), body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), body.email, otp, 'register', now + 300).run();
        await sendOtpEmail(env, body.email, otp, 'register');
        return jsonOk({ message: "Registrasi sukses. Cek Email Anda." });
      } catch(e) { return jsonError("Email atau No HP sudah terdaftar."); }
    }

    // === REQUEST & VERIFY OTP ===
    if (action === "request-otp") {
      const user = await findUser(body.identifier);
      if(!user && body.purpose !== 'register') return jsonError("Akun tidak ditemukan.", 404);
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=?").bind(body.identifier).run();
      await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), body.identifier, otp, body.purpose || 'login', now + 300).run();
      if(body.identifier.includes('@')) await sendOtpEmail(env, body.identifier, otp, body.purpose);
      return jsonOk({ message: "Kode OTP terkirim (Cek Email)" });
    }

    if (action === "verify-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP salah atau kadaluarsa.");
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      
      if(otpRow.purpose === 'register') {
        await env.DB.prepare("UPDATE users SET status='active' WHERE email=? OR phone=?").bind(body.identifier, body.identifier).run();
        return jsonOk({ message: "Akun aktif." });
      }
    }

    if (action === "login-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose='login' AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP salah.");
      const user = await findUser(body.identifier);
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      const sid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + 604800).run();
      return jsonOk({ message: "Login Sukses", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
    }

    // === SET PIN ===
    if (action === "set-pin") {
      const hashedPin = await hashData(body.pin);
      const user = await findUser(body.identifier);
      await env.DB.prepare("UPDATE users SET pin_hash=? WHERE email=? OR phone=?").bind(hashedPin, body.identifier, body.identifier).run();
      return jsonOk({ message: "PIN berhasil disimpan.", redirect_url: user ? getPortalUrl(user.role) : "https://dashboard.orlandmanagement.com" });
    }

    return jsonError("Endpoint tidak valid.", 404);
  } catch(e) { return jsonError("Server Error", 500); }
}
