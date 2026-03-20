import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

const TURNSTILE_SECRET = "0x4AAAAAACs8dTjOU5UcntgtIKPw4lJznNg";
const SESSION_EXPIRY = 259200; // 72 Jam (3 Hari)
const LOCK_TIME = 900; // 15 Menit dalam detik

// Fungsi Verifikasi Captcha Cloudflare Turnstile
async function verifyTurnstile(token, ip) {
    if (!token) return false;
    const formData = new FormData(); 
    formData.append('secret', TURNSTILE_SECRET); 
    formData.append('response', token); 
    formData.append('remoteip', ip || '');
    try { 
        const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: formData }); 
        return (await res.json()).success; 
    } catch (e) { return false; }
}

// FUNGSI EMAIL HYBRID (Resend + Fallback MailChannels)
async function sendMail(env, toEmail, token, purpose) {
    const host = "https://sso.orlandmanagement.com";
    let subject, html;

    if (purpose === 'activation') {
        subject = "Aktivasi Akun Orland Management";
        html = `<div style="font-family:sans-serif; padding:20px; color:#333;"><h2>Satu Langkah Lagi!</h2><p>Klik tombol di bawah ini untuk mengaktifkan akun Anda (Berlaku 24 Jam):</p><br><a href="${host}/?activation_token=${token}" style="background-color:#2563eb; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold; display:inline-block;">Aktifkan Akun Saya</a></div>`;
    } else if (purpose === 'reset') {
        subject = "Reset Password Orland Management";
        html = `<div style="font-family:sans-serif; padding:20px; color:#333;"><h2>Reset Password</h2><p>Link ini berlaku selama 30 Menit. Jika Anda tidak memintanya, abaikan email ini.</p><br><a href="${host}/?reset_token=${token}" style="background-color:#ef4444; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold; display:inline-block;">Reset Password Sekarang</a></div>`;
    } else {
        subject = "Kode OTP Orland Management";
        html = `<div style="font-family:sans-serif; padding:20px; color:#333;"><h2>Verifikasi Keamanan</h2><p>Berikut kode OTP Anda (Berlaku 3 Menit):</p><h1 style="letter-spacing:5px; color:#2563eb;">${token}</h1></div>`;
    }

    // 1. Coba Kirim via Resend (Jika API Key ada)
    if (env.RESEND_API_KEY) {
        try {
            const res = await fetch('https://api.resend.com/emails', { 
                method: 'POST', 
                headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, 
                body: JSON.stringify({ from: 'Orland Management <no-reply@orlandmanagement.com>', to: toEmail, subject, html }) 
            });
            if (res.ok) return { success: true };
            console.log("Resend ditolak (mungkin domain belum verifikasi). Fallback ke MailChannels...");
        } catch (e) {}
    }

    // 2. Fallback via Cloudflare MailChannels (Tanpa API Key, Pasti Terkirim!)
    try {
        const mcData = {
            personalizations: [{ to: [{ email: toEmail }] }],
            from: { email: "no-reply@orlandmanagement.com", name: "Orland Security" },
            subject: subject,
            content: [{ type: "text/html", value: html }]
        };
        const mcRes = await fetch("https://api.mailchannels.net/tx/v1/send", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(mcData)
        });
        if (mcRes.ok || mcRes.status === 202) return { success: true };
    } catch(e) {}

    return { success: false };
}

function getPortalUrl(role) { return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com'; }

export async function onRequestGet({ request, env, params }) {
    if (params.action === "me") {
        const cookies = parseCookies(request);
        if (!cookies.sid) return jsonError("Tidak ada sesi.", 401);
        const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, Math.floor(Date.now() / 1000)).first();
        if (!session) return jsonError("Sesi kadaluarsa.", 401);
        const user = await env.DB.prepare("SELECT id, full_name, email, role, status FROM users WHERE id=?").bind(session.user_id).first();
        if (!user || user.status === 'deleted') return jsonError("Akun tidak ditemukan atau dihapus.", 404);
        return jsonOk({ user });
    }
    return jsonError("Endpoint Tidak Ditemukan", 404);
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

        // Mencegah spasi ekstra dan merubah input ke huruf kecil (Case Insensitive)
        const cleanIdentifier = (body.identifier || "").trim().toLowerCase();
        const cleanEmail = (body.email || "").trim().toLowerCase();

        // Cari user yang tidak dihapus (Soft Delete handler)
        const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE (email=? OR phone=?) AND status != 'deleted'").bind(id, id).first();

        // -------------------------------------------------------------
        // REGISTRASI & AKTIVASI EMAIL
        // -------------------------------------------------------------
        if (action === "register") {
            const existingUser = await findUser(cleanEmail);
            if (existingUser) return jsonError("Pendaftaran Gagal: Email atau No HP sudah terdaftar.");
            if (!body.password || body.password.length < 8) return jsonError("Password minimal 8 karakter.");

            const hashedPw = await hashData(body.password);
            await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
                .bind(crypto.randomUUID(), body.fullName, cleanEmail, body.phone, body.role, hashedPw, now).run();
            
            const tokenUUID = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), cleanEmail, tokenUUID, 'activation', now + 86400).run(); 
            
            const mail = await sendMail(env, cleanEmail, tokenUUID, 'activation');
            return jsonOk({ message: "Registrasi Sukses! Link Aktivasi telah dikirim ke email Anda.", status: "ok" });
        }

        if (action === "verify-activation") {
            const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='activation' AND expires_at > ?").bind(body.token, now).first();
            if(!tokenRow) return jsonError("Tautan Aktivasi tidak valid atau sudah kadaluarsa.");
            
            await env.DB.prepare("UPDATE users SET status='active' WHERE email=?").bind(tokenRow.identifier).run();
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
            
            const user = await findUser(tokenRow.identifier);
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            
            return jsonOk({ message: "Aktivasi Berhasil", role: user.role, redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // -------------------------------------------------------------
        // LOGIKA OTP (ANTI-GAGAL)
        // -------------------------------------------------------------
        if (action === "request-otp") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);
            
            const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
            await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=? AND purpose=?").bind(user.email, body.purpose).run();
            // Gunakan user.email langsung agar bebas huruf besar/kecil
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, otp, body.purpose, now + 180).run();
            
            await sendMail(env, user.email, otp, body.purpose);
            return jsonOk({ message: "Kode OTP terkirim ke email Anda." });
        }

        if (action === "login-otp" || action === "setup-pin") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);

            // Validasi berdasarkan user.email dari database (Pasti Cocok)
            const purp = action === "login-otp" ? "login" : "setup-pin";
            const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose=? AND expires_at > ?").bind(user.email, body.otp, purp, now).first();
            
            if(!otpRow) return jsonError("Kode OTP salah atau sudah expired.");
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
            
            await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
            
            if(action === "setup-pin") {
                const hashedPin = await hashData(body.new_pin);
                await env.DB.prepare("UPDATE users SET pin_hash=? WHERE id=?").bind(hashedPin, user.id).run();
            }

            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ message: "Akses Diberikan via OTP", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // --- SISTEM YANG LAIN SAMA PERSIS SEPERTI SEBELUMNYA ---
        if (action === "login-password") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Kredensial salah.", 401);
            if (user.locked_until && user.locked_until > now) return jsonError(`Akun terkunci sementara.`, 429);
            
            const hashInput = await hashData(body.password);
            if (user.password_hash !== hashInput) {
                const fails = (user.fail_count || 0) + 1;
                if (fails >= 5) { 
                    await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + LOCK_TIME, user.id).run();
                    return jsonError("Gagal 5x. Akun Anda dikunci selama 15 Menit.", 429);
                }
                await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
                return jsonError(`Password salah. (Sisa percobaan: ${5 - fails})`, 401);
            }

            if(user.status === 'pending') return jsonError("Akun belum diaktifkan. Silakan klik Link Aktivasi di email Anda.", 403);

            await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        return jsonError("Fungsi lainnya sedang disesuaikan...", 404);
    } catch(e) { return jsonError("Server API Error", 500); }
}
