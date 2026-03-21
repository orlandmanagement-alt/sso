import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

const TURNSTILE_SECRET = "0x4AAAAAACs8dTjOU5UcntgtIKPw4lJznNg";
const SESSION_EXPIRY = 259200;

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

async function sendMail(env, toEmail, token, purpose) {
    // Simulasi pengiriman email untuk environment production (MailChannels logic diringkas)
    return { success: true };
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
        return jsonOk({ status: "ok", user });
    }
    return jsonError("Endpoint Tidak Ditemukan", 404);
}

export async function onRequestPost({ request, env, params }) {
    try {
        const action = params.action;
        const body = await request.json().catch(() => ({}));
        const now = Math.floor(Date.now() / 1000); 
        const clientIp = request.headers.get("cf-connecting-ip") || "unknown_ip";

        const cleanIdentifier = (body.identifier || "").trim().toLowerCase();
        const cleanEmail = (body.email || "").trim().toLowerCase();

        const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE (email=? OR phone=?) AND status != 'deleted'").bind(id, id).first();

        if (action === "logout") {
            const cookies = parseCookies(request);
            if (cookies.sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookies.sid).run();
            return jsonOk({ status: "ok", message: "Logout Sukses" }, clearSessionCookie());
        }

        if (action === "register") {
            const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
            if(!isHuman) return jsonError("Verifikasi keamanan gagal.");

            const existingUser = await findUser(cleanEmail);
            if (existingUser) return jsonError("Email atau No HP sudah terdaftar.");
            
            const hashedPw = await hashData(body.password);
            await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
                .bind(crypto.randomUUID(), body.fullName, cleanEmail, body.phone, body.role, hashedPw, now).run();
            
            return jsonOk({ status: "ok", message: "Registrasi Sukses!" });
        }

        if (action === "verify-activation") {
            const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='activation' AND expires_at > ?").bind(body.token, now).first();
            if(!tokenRow) return jsonError("Tautan Aktivasi tidak valid.");
            
            await env.DB.prepare("UPDATE users SET status='active' WHERE email=?").bind(tokenRow.identifier).run();
            const user = await findUser(tokenRow.identifier);
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            
            return jsonOk({ status: "ok", role: user.role, redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        if (action === "login-password") {
            const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
            if(!isHuman) return jsonError("Verifikasi keamanan gagal.");

            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Kredensial salah.", 401);
            if (user.locked_until && user.locked_until > now) return jsonError(`Akun terkunci.`, 429);
            
            const hashInput = await hashData(body.password);
            if (user.password_hash !== hashInput) return jsonError("Password salah.", 401);
            if(user.status === 'pending') return jsonError("Akun belum diaktifkan.", 403);

            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        if (action === "request-otp") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, otp, body.purpose, now + 180).run();
            return jsonOk({ status: "ok", message: "OTP Terkirim." });
        }

        if (action === "login-otp" || action === "setup-pin") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            const purp = action === "login-otp" ? "login" : "setup-pin";
            const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose=? AND expires_at > ?").bind(user.email, body.otp, purp, now).first();
            
            if(!otpRow) return jsonError("OTP salah/expired.");
            
            if(action === "setup-pin") {
                const hashedPin = await hashData(body.new_pin);
                await env.DB.prepare("UPDATE users SET pin_hash=? WHERE id=?").bind(hashedPin, user.id).run();
            }

            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        return jsonError("Aksi tidak dikenal.", 404);
    } catch(e) { return jsonError("Server API Error", 500); }
}
