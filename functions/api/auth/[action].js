import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

const TURNSTILE_SECRET = "0x4AAAAAACs8dTjOU5UcntgtIKPw4lJznNg"; // Sesuaikan jika perlu
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
    const host = "https://sso.orlandmanagement.com"; 
    let subject, html;

    if (purpose === 'activation') {
        subject = "Aktivasi Akun Orland Management";
        html = `<div style="font-family:sans-serif; padding:20px; color:#333;"><h2>Satu Langkah Lagi!</h2><p>Klik tombol di bawah ini untuk mengaktifkan akun Anda (Berlaku 24 Jam):</p><br><a href="${host}/?activation_token=${token}" style="background-color:#2563eb; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold; display:inline-block;">Aktifkan Akun Saya</a></div>`;
    } else if (purpose === 'reset') {
        subject = "Reset Password Orland Management";
        html = `<div style="font-family:sans-serif; padding:20px; color:#333;"><h2>Reset Password</h2><p>Link ini berlaku selama 30 Menit.</p><br><a href="${host}/?reset_token=${token}" style="background-color:#ef4444; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold; display:inline-block;">Reset Password Sekarang</a></div>`;
    } else {
        subject = "Kode OTP Orland Management";
        html = `<div style="font-family:sans-serif; padding:20px; color:#333;"><h2>Verifikasi Keamanan</h2><p>Berikut kode OTP Anda (Berlaku 3 Menit):</p><h1 style="letter-spacing:5px; color:#2563eb;">${token}</h1></div>`;
    }

    // 1. PRIORITAS UTAMA: Gunakan Resend API jika secret tersedia
    if (env.RESEND_API_KEY) {
        try {
            const resendRes = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${env.RESEND_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    from: 'Orland Management <no-reply@orlandmanagement.com>', 
                    to: toEmail,
                    subject: subject,
                    html: html
                })
            });
            
            if (resendRes.ok) {
                return { success: true };
            } else {
                // Jika Resend menolak (misal error 403), kita log errornya secara internal
                const errorText = await resendRes.text();
                console.error("Resend API Error:", errorText);
            }
        } catch (e) {
            console.error("Resend Fetch Failed:", e);
        }
    }

    // 2. FALLBACK: MailChannels (Jika Resend gagal/belum terkonfigurasi)
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
        return { success: mcRes.ok || mcRes.status === 202 };
    } catch(e) {
        return { success: false };
    }
}


function getPortalUrl(role) { return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com'; }

export async function onRequestGet({ request, env, params }) {
    if (params.action === "me") {
        const cookies = parseCookies(request);
        if (!cookies.sid) return jsonError("Tidak ada sesi.", 401);
        const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, Math.floor(Date.now() / 1000)).first();
        if (!session) return jsonError("Sesi kadaluarsa.", 401);
        const user = await env.DB.prepare("SELECT id, full_name, email, role, status FROM users WHERE id=?").bind(session.user_id).first();
        if (!user || user.status === 'deleted') return jsonError("Akun tidak ditemukan.", 404);
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

        // 1. LOGOUT
        if (action === "logout") {
            const cookies = parseCookies(request);
            if (cookies.sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookies.sid).run();
            return jsonOk({ status: "ok", message: "Logout Sukses" }, clearSessionCookie());
        }

        // 2. REGISTER
        if (action === "register") {
            const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
            if(!isHuman) return jsonError("Verifikasi keamanan gagal.");
            const existingUser = await findUser(cleanEmail);
            if (existingUser) return jsonError("Email sudah terdaftar.");
            
            const hashedPw = await hashData(body.password);
            await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
                .bind(crypto.randomUUID(), body.fullName, cleanEmail, body.phone, body.role, hashedPw, now).run();
            
            // SIMPAN TOKEN & KIRIM EMAIL AKTIVASI
            const tokenUUID = crypto.randomUUID().replace(/-/g, '');
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), cleanEmail, tokenUUID, 'activation', now + 86400).run();
            await sendMail(env, cleanEmail, tokenUUID, 'activation');
            
            return jsonOk({ status: "ok", message: "Registrasi Sukses! Cek Email." });
        }

        // 3. AKTIVASI EMAIL
        if (action === "verify-activation") {
            const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='activation' AND expires_at > ?").bind(body.token, now).first();
            if(!tokenRow) return jsonError("Tautan Aktivasi tidak valid/kadaluarsa.");
            await env.DB.prepare("UPDATE users SET status='active' WHERE email=?").bind(tokenRow.identifier).run();
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
            
            const user = await findUser(tokenRow.identifier);
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", role: user.role, redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // 4. LOGIN PASSWORD
        if (action === "login-password") {
            const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
            if(!isHuman) return jsonError("Verifikasi keamanan gagal.");
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Kredensial salah.", 401);
            if (user.locked_until && user.locked_until > now) return jsonError(`Akun terkunci. Coba lagi nanti.`, 429);
            
            const hashInput = await hashData(body.password);
            if (user.password_hash !== hashInput) {
                const fails = (user.fail_count || 0) + 1;
                if (fails >= 5) {
                    await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + 900, user.id).run();
                    return jsonError("Gagal 5x. Akun dikunci 15 menit.", 429);
                }
                await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
                return jsonError(`Password salah. (Sisa percobaan: ${5 - fails})`, 401);
            }

            // ==========================================
            // LOGIKA BARU: TOKEN 24 JAM TIDAK DIHAPUS
            // ==========================================
            if(user.status === 'pending') {
                // 1. Cek apakah ada token aktivasi yang MENGENDAP dan MASIH HIDUP (belum 24 jam)
                let activeTokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND purpose='activation' AND expires_at > ?").bind(user.email, now).first();
                
                let tokenUUID;
                
                if (activeTokenRow) {
                    // Jika MASIH ADA, gunakan token yang sama persis! Jangan di-delete!
                    tokenUUID = activeTokenRow.code;
                } else {
                    // Jika TIDAK ADA (atau sudah lewat 24 jam dan hancur otomatis), buat baru.
                    tokenUUID = crypto.randomUUID().replace(/-/g, '');
                    
                    // Bersihkan sisa-sisa token kadaluarsa (Housekeeping)
                    await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=? AND purpose=?").bind(user.email, 'activation').run();
                    
                    // Simpan token baru dengan masa hidup 24 Jam (86400 detik)
                    await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, tokenUUID, 'activation', now + 86400).run();
                }
                
                // Kirimkan token via email (entah itu token yang masih hidup, atau token baru)
                await sendMail(env, user.email, tokenUUID, 'activation');
                
                return jsonError("Akun belum aktif! Tautan aktivasi (berlaku 24 jam) telah dikirim ke email Anda.", 403);
            }
            // ==========================================
            
            await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }


       // 5. REQUEST OTP UMUM
        if (action === "request-otp") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
            
            // TAMBAHAN: Hapus OTP lama agar tidak menumpuk
            await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=? AND purpose=?").bind(user.email, body.purpose).run();
            
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, otp, body.purpose, now + 180).run();
            await sendMail(env, user.email, otp, body.purpose);
            
            return jsonOk({ status: "ok", message: "OTP Terkirim." });
        }
        
        // 6. LOGIN OTP & SETUP PIN
        if (action === "login-otp" || action === "setup-pin") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            const purp = action === "login-otp" ? "login" : "setup-pin";
            const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose=? AND expires_at > ?").bind(user.email, body.otp, purp, now).first();
            if(!otpRow) return jsonError("OTP salah/expired.");
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
            
            if(action === "setup-pin") {
                const hashedPin = await hashData(body.new_pin);
                await env.DB.prepare("UPDATE users SET pin_hash=? WHERE id=?").bind(hashedPin, user.id).run();
            }
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // 7. CHECK PIN
        if (action === "check-pin") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            return jsonOk({ status: "ok", has_pin: !!user.pin_hash, email: user.email });
        }

        // 8. LOGIN PIN
        if (action === "login-pin") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            const hashInput = await hashData(body.pin);
            if(user.pin_hash !== hashInput) return jsonError("PIN salah.");
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // 9. FORGOT PASSWORD REQUEST
        if (action === "request-reset") {
            const user = await findUser(cleanIdentifier);
            if(!user) return jsonError("Akun tidak ditemukan.");
            const tokenUUID = crypto.randomUUID().replace(/-/g, '');
            
            // TAMBAHAN: Hapus link reset lama
            await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=? AND purpose=?").bind(user.email, 'reset').run();
            
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, tokenUUID, 'reset', now + 1800).run();
            await sendMail(env, user.email, tokenUUID, 'reset');
            
            return jsonOk({ status: "ok", message: "Link reset terkirim." });
        }


        // 10. SUBMIT NEW PASSWORD
        if (action === "reset-password") {
            const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='reset' AND expires_at > ?").bind(body.token, now).first();
            if(!tokenRow) return jsonError("Token tidak valid/kadaluarsa.");
            const hashedPw = await hashData(body.new_password);
            await env.DB.prepare("UPDATE users SET password_hash=? WHERE email=?").bind(hashedPw, tokenRow.identifier).run();
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
            
            // TAMBAHAN: Hapus semua sesi user ini (Logout dari semua perangkat)
            const user = await findUser(tokenRow.identifier);
            if (user) await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(user.id).run();

            return jsonOk({ status: "ok", message: "Password berhasil diubah." });
        }


        // 11. GOOGLE LOGIN
        if (action === "google-login") {
            try {
                const payloadBase64 = body.credential.split('.')[1];
                const decodedPayload = JSON.parse(atob(payloadBase64.replace(/-/g, '+').replace(/_/g, '/')));
                const email = decodedPayload.email;
                const name = decodedPayload.name;
                const googleId = decodedPayload.sub;

                const user = await env.DB.prepare("SELECT * FROM users WHERE email=? OR social_id=?").bind(email, googleId).first();
                if (user) {
                    const sid = crypto.randomUUID();
                    await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
                    return jsonOk({ status: "ok", is_new: false, redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
                } else {
                    return jsonOk({ status: "ok", is_new: true, email, name, social_id: googleId });
                }
            } catch (e) { return jsonError("Gagal memverifikasi Google Token."); }
        }

        // 12. COMPLETE SOCIAL REGISTER
        if (action === "social-complete") {
            const existingUser = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(body.email).first();
            if (existingUser) return jsonError("Email sudah terdaftar.");
            const userId = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, social_provider, social_id, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)")
                .bind(userId, body.name, body.email, `social_${Date.now()}`, body.role, body.provider, body.social_id, 'active', now).run();
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, userId, body.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ status: "ok", redirect_url: getPortalUrl(body.role) }, makeSessionCookie(sid));
        }

        return jsonError(`Aksi tidak dikenal.`, 404);
    } catch(e) { return jsonError("Server API Error", 500); }
}
