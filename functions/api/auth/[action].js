import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie, clearSessionCookie, parseCookies } from "../../_lib/cookies.js";

// ============================================================================
// KONFIGURASI GLOBAL & KEAMANAN
// ============================================================================
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

// Fungsi Kirim Email (Resend API) Terpusat
async function sendMail(env, toEmail, token, purpose) {
    if (!env.RESEND_API_KEY) {
        console.warn(`[WARNING] RESEND_API_KEY kosong! Token untuk ${toEmail}: ${token}`);
        return { success: false, reason: "NO_API_KEY" };
    }
    
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

    try {
        const res = await fetch('https://api.resend.com/emails', { 
            method: 'POST', 
            headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ 
                from: 'Orland Management <no-reply@orlandmanagement.com>', 
                to: toEmail, subject, html 
            }) 
        });
        if (!res.ok) { 
            console.error("Resend API Error:", await res.json()); 
            console.warn(`[FALLBACK LOG] Token untuk ${toEmail}: ${token}`);
            return { success: false }; 
        } 
        return { success: true };
    } catch (e) { 
        console.error("Fetch Error:", e); 
        return { success: false }; 
    }
}

function getPortalUrl(role) { return role === 'client' ? 'https://client.orlandmanagement.com' : 'https://talent.orlandmanagement.com'; }

// ============================================================================
// METHOD: GET (Cek Sesi)
// ============================================================================
export async function onRequestGet({ request, env, params }) {
    if (params.action === "me") {
        const cookies = parseCookies(request);
        if (!cookies.sid) return jsonError("Tidak ada sesi.", 401);
        
        // Pengecekan JWT Database-backed (Masa aktif 3 Hari)
        const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND expires_at > ?").bind(cookies.sid, Math.floor(Date.now() / 1000)).first();
        if (!session) return jsonError("Sesi kadaluarsa.", 401);
        
        const user = await env.DB.prepare("SELECT id, full_name, email, role, status FROM users WHERE id=?").bind(session.user_id).first();
        if (!user || user.status === 'deleted') return jsonError("Akun tidak ditemukan atau telah dihapus.", 404);
        
        return jsonOk({ user });
    }
    return jsonError("Endpoint Tidak Ditemukan", 404);
}

// ============================================================================
// METHOD: POST (Logika Utama Autentikasi)
// ============================================================================
export async function onRequestPost({ request, env, params }) {
    try {
        const action = params.action;
        if (action === "logout") {
            const cookies = parseCookies(request);
            if (cookies.sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookies.sid).run();
            return jsonOk({ message: "Logout Sukses" }, clearSessionCookie());
        }

        const body = await request.json().catch(() => ({}));
        const now = Math.floor(Date.now() / 1000); // Waktu seragam (Epoch Detik)
        const clientIp = request.headers.get("cf-connecting-ip") || "unknown_ip";

        // --- 1. RATE LIMITING (Mencegah Bot / Brute Force) ---
        try {
            await env.DB.prepare("DELETE FROM ip_rate_limit WHERE expires_at < ?").bind(now).run();
            const rl = await env.DB.prepare("SELECT count FROM ip_rate_limit WHERE ip = ?").bind(clientIp).first();
            if (rl && rl.count >= 10) return jsonError("Terlalu banyak request. IP Anda diblokir sementara.", 429);
            await env.DB.prepare("INSERT INTO ip_rate_limit (ip, count, expires_at) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET count = count + 1").bind(clientIp, now + 60).run();
        } catch (e) { /* Abaikan jika tabel belum siap */ }

        // Helper Pencarian User (Abaikan user yang terkena Soft Delete)
        const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE (email=? OR phone=?) AND status != 'deleted'").bind(id, id).first();

        // --- 2. ALUR LOGIN SOSIAL MEDIA (Google) ---
        if (action === "google-login") {
            const tokenRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${body.credential}`);
            const gData = await tokenRes.json();
            if (!tokenRes.ok || !gData.email) return jsonError("Autentikasi Google Gagal.");
            
            let user = await findUser(gData.email);
            
            // SKENARIO B: Belum Terdaftar -> Kirim sinyal ke UI untuk menampilkan popup Role
            if (!user) {
                return jsonOk({ 
                    is_new: true, 
                    email: gData.email, 
                    name: gData.name, 
                    social_id: gData.sub, 
                    provider: 'google' 
                });
            }
            
            // SKENARIO A: Sudah Terdaftar -> Buat JWT/Sesi & Redirect
            if(user.status === 'pending') await env.DB.prepare("UPDATE users SET status='active' WHERE id=?").bind(user.id).run(); // Auto verify
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ message: "Login Google Sukses!", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // --- 3. LANJUTAN SOCIAL LOGIN (Pilih Peran) ---
        if (action === "social-complete") {
            if (!body.email || !body.role) return jsonError("Data tidak lengkap.", 400);
            
            // Cek apakah email sudah ada untuk mencegah duplikasi
            const exist = await findUser(body.email);
            if(exist) return jsonError("Email sudah terdaftar. Silakan langsung login.", 400);

            const newUserId = crypto.randomUUID();
            // Daftar otomatis via Google (Tanpa Password, Status ACTIVE)
            await env.DB.prepare("INSERT INTO users (id, full_name, email, role, social_provider, social_id, status, created_at) VALUES (?,?,?,?,?,?,'active',?)")
                .bind(newUserId, body.name || 'User', body.email, body.role, body.provider || 'google', body.social_id || null, now).run();
            
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)")
                .bind(sid, newUserId, body.role, now, now + SESSION_EXPIRY).run();
            
            return jsonOk({ message: "Pendaftaran Sukses!", redirect_url: getPortalUrl(body.role) }, makeSessionCookie(sid));
        }

        // --- 4. PROTEKSI CAPTCHA UNTUK FORM MANUAL ---
        if (["login-password", "register"].includes(action)) {
            const isHuman = await verifyTurnstile(body.turnstile_token, clientIp);
            if (!isHuman) return jsonError("Validasi keamanan gagal (Bot Terdeteksi).", 403);
        }

        // --- 5. ALUR REGISTRASI (Email/No HP) ---
        if (action === "register") {
            const existingUser = await findUser(body.email);
            if (existingUser) return jsonError("Pendaftaran Gagal: Email atau No HP sudah terdaftar.");
            if (!body.password || body.password.length < 8) return jsonError("Password minimal 8 karakter.");

            const hashedPw = await hashData(body.password);
            // Simpan status UNVERIFIED (Pending)
            await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at) VALUES (?,?,?,?,?,?,'pending',?)")
                .bind(crypto.randomUUID(), body.fullName, body.email, body.phone, body.role, hashedPw, now).run();
            
            const tokenUUID = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), body.email, tokenUUID, 'activation', now + 86400).run(); // 24 Jam
            
            const mail = await sendMail(env, body.email, tokenUUID, 'activation');
            return jsonOk({ message: mail.success ? "Link Aktivasi telah dikirim ke Email Anda." : "Registrasi sukses! (Email gagal terkirim, cek logs backend).", sim_token: mail.success ? undefined : tokenUUID });
        }

        // --- 6. AKTIVASI EMAIL (MAGIC LINK) ---
        if (action === "verify-activation") {
            const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='activation' AND expires_at > ?").bind(body.token, now).first();
            if(!tokenRow) return jsonError("Tautan Aktivasi tidak valid atau sudah kadaluarsa (Lebih dari 24 Jam).");
            
            // Ubah Status jadi ACTIVE
            await env.DB.prepare("UPDATE users SET status='active' WHERE email=?").bind(tokenRow.identifier).run();
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
            
            const user = await findUser(tokenRow.identifier);
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            
            return jsonOk({ message: "Aktivasi Berhasil", role: user.role, redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // --- 7. ALUR LOGIN REGULER (Email & Password) ---
        if (action === "login-password") {
            const user = await findUser(body.identifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);
            
            // Cek Lock 15 Menit
            if (user.locked_until && user.locked_until > now) {
                const minLeft = Math.ceil((user.locked_until - now) / 60);
                return jsonError(`Akun terkunci sementara karena salah password berkali-kali. Coba lagi dalam ${minLeft} menit.`, 429);
            }
            
            const hashInput = await hashData(body.password);
            if (user.password_hash !== hashInput) {
                const fails = (user.fail_count || 0) + 1;
                if (fails >= 5) { // MAX 5x GAGAL
                    await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + LOCK_TIME, user.id).run();
                    return jsonError("Gagal 5x berturut-turut. Akun Anda dikunci selama 15 Menit.", 429);
                }
                await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
                return jsonError(`Password salah. (Sisa percobaan: ${5 - fails})`, 401);
            }

            // Validasi Status Aktif
            if(user.status === 'pending') return jsonError("Akun belum diaktifkan. Silakan cek email Anda untuk Link Aktivasi.", 403);

            // Berhasil: Reset Fail Count & Buat Sesi
            await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // --- 8. ALUR LUPA PASSWORD (LINK 30 MENIT) ---
        if (action === "request-reset") {
            const user = await findUser(body.identifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);
            
            const tokenUUID = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
            await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=? AND purpose='reset'").bind(user.email).run();
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, tokenUUID, 'reset', now + 1800).run(); // Valid 30 Mnt
            
            const mail = await sendMail(env, user.email, tokenUUID, 'reset');
            return jsonOk({ message: mail.success ? "Tautan Reset Password telah dikirim ke Email Anda." : "Sistem email gangguan (Cek Logs).", sim_token: mail.success ? undefined : tokenUUID });
        }

        if (action === "reset-password") {
            const tokenRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE code=? AND purpose='reset' AND expires_at > ?").bind(body.token, now).first();
            if(!tokenRow) return jsonError("Tautan Reset sudah kadaluarsa (Lebih dari 30 Menit) atau pernah digunakan.");
            
            if (!body.new_password || body.new_password.length < 8) return jsonError("Password minimal 8 karakter.");

            const hashedPw = await hashData(body.new_password);
            await env.DB.prepare("UPDATE users SET password_hash=?, fail_count=0, locked_until=NULL WHERE email=?").bind(hashedPw, tokenRow.identifier).run();
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(tokenRow.id).run();
            
            return jsonOk({ message: "Password berhasil diubah. Silakan Login." });
        }

        // --- 9. ALUR LOGIN OTP (3 MENIT) ---
        if (action === "request-otp") {
            const user = await findUser(body.identifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);
            
            const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6 Digit Angka
            await env.DB.prepare("DELETE FROM otp_requests WHERE identifier=?").bind(user.email).run();
            await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), user.email, otp, body.purpose, now + 180).run(); // Valid 3 Mnt
            
            const mail = await sendMail(env, user.email, otp, body.purpose);
            return jsonOk({ message: "Kode OTP terkirim" });
        }

        if (action === "login-otp") {
            const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose='login' AND expires_at > ?").bind(body.identifier, body.otp, now).first();
            if(!otpRow) return jsonError("Kode OTP salah atau sudah lewat dari 3 Menit.");
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
            
            const user = await findUser(body.identifier);
            await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
            
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ message: "Akses Diberikan via OTP", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        // --- 10. ALUR LOGIN PIN (HANYA ANGKA, LOCK 3X) ---
        if (action === "check-pin") {
            const user = await findUser(body.identifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);
            return jsonOk({ has_pin: user.pin_hash ? true : false, email: user.email });
        }

        if (action === "setup-pin") {
            const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND purpose='setup-pin' AND expires_at > ?").bind(body.identifier, body.otp, now).first();
            if(!otpRow) return jsonError("OTP Keamanan tidak valid.");
            if (!body.new_pin || !/^\d{6}$/.test(body.new_pin)) return jsonError("PIN harus berupa 6 digit angka numerik."); // Validasi Numerik
            
            await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
            
            const user = await findUser(body.identifier);
            const hashedPin = await hashData(body.new_pin);
            await env.DB.prepare("UPDATE users SET pin_hash=? WHERE id=?").bind(hashedPin, user.id).run();
            
            const sid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)").bind(sid, user.id, user.role, now, now + SESSION_EXPIRY).run();
            return jsonOk({ message: "PIN Berhasil Disimpan!", redirect_url: getPortalUrl(user.role) }, makeSessionCookie(sid));
        }

        if (action === "login-pin") {
            const user = await findUser(body.identifier);
            if(!user) return jsonError("Akun tidak ditemukan.", 404);
            
            if (user.locked_until && user.locked_until > now) return jsonError("Akses PIN diblokir. Gunakan Login Password.", 429);
            
            const hashInput = await hashData(body.pin);
            if (user.pin_hash !== hashInput) {
                const fails = (user.fail_count || 0) + 1;
                if (fails >= 3) { // MAX 3x GAGAL UNTUK PIN
                    await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, now + LOCK_TIME, user.id).run();
                    return jsonError("PIN Salah 3x berturut-turut. Akun dikunci 15 menit untuk keamanan.", 429);
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

        return jsonError("Endpoint API tidak valid", 404);
    } catch(e) { 
        console.error("API Crash:", e);
        return jsonError("Server Error Keseluruhan", 500); 
    }
}
