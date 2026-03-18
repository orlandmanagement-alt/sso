import { jsonOk, jsonError } from "../../_lib/response.js";
import { hashData } from "../../_lib/crypto.js";
import { makeSessionCookie } from "../../_lib/cookies.js";

export async function onRequestPost({ request, env, params }) {
  try {
    const action = params.action;
    const body = await request.json().catch(() => ({}));
    const now = Math.floor(Date.now() / 1000);

    const findUser = async (id) => await env.DB.prepare("SELECT * FROM users WHERE email=? OR phone=?").bind(id, id).first();

    // ==========================================
    // LOGIKA LOGIN (Dengan Anti Brute-Force)
    // ==========================================
    if (action === "login-password" || action === "login-pin") {
      const user = await findUser(body.identifier);
      if(!user) return jsonError("Akun tidak ditemukan.", 404);
      
      // 1. CEK APAKAH AKUN SEDANG TERKUNCI
      if (user.locked_until && user.locked_until > now) {
        const sisaMenit = Math.ceil((user.locked_until - now) / 60);
        return jsonError(`Akun terkunci demi keamanan. Coba lagi dalam ${sisaMenit} menit.`, 429);
      }
      
      if(user.status !== 'active') return jsonError("Akun belum diverifikasi.", 403);

      const hashInput = await hashData(body.password || body.pin);
      const isPasswordWrong = action === "login-password" && user.password_hash !== hashInput;
      const isPinWrong = action === "login-pin" && user.pin_hash !== hashInput;

      // 2. JIKA PASSWORD/PIN SALAH (Hitung Kegagalan)
      if (isPasswordWrong || isPinWrong) {
        const fails = (user.fail_count || 0) + 1;
        if (fails >= 5) {
          // Kunci akun selama 15 menit (900 detik)
          const lockTime = now + 900;
          await env.DB.prepare("UPDATE users SET fail_count=?, locked_until=? WHERE id=?").bind(fails, lockTime, user.id).run();
          return jsonError("Terlalu banyak percobaan gagal. Akun Anda dikunci selama 15 menit.", 429);
        } else {
          await env.DB.prepare("UPDATE users SET fail_count=? WHERE id=?").bind(fails, user.id).run();
          return jsonError(`Kredensial salah. Kesempatan tersisa ${5 - fails} kali.`, 401);
        }
      }

      // 3. JIKA LOGIN SUKSES (Reset Hitungan Gagal & Buat Sesi)
      if (user.fail_count > 0 || user.locked_until !== null) {
        await env.DB.prepare("UPDATE users SET fail_count=0, locked_until=NULL WHERE id=?").bind(user.id).run();
      }

      const sid = crypto.randomUUID();
      const expires = now + (7 * 24 * 60 * 60);
      await env.DB.prepare("INSERT INTO sessions (id, user_id, role, created_at, expires_at) VALUES (?,?,?,?,?)")
        .bind(sid, user.id, user.role, now, expires).run();

      const cookieStr = makeSessionCookie(sid);
      return jsonOk({ message: "Login Sukses", role: user.role, redirect_url: "https://dashboard.orlandmanagement.com" }, cookieStr);
    }

    // ==========================================
    // LOGIKA REGISTER, OTP, & SOCIAL (Tetap Sama)
    // ==========================================
    if (action === "register") {
      const hashedPw = await hashData(body.password);
      const id = crypto.randomUUID();
      try {
        await env.DB.prepare("INSERT INTO users (id, full_name, email, phone, role, password_hash, status, created_at, fail_count) VALUES (?,?,?,?,?,?,?,'pending',?, 0)")
          .bind(id, body.fullName, body.email, body.phone, body.role, hashedPw, body.provider||null, now).run();
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await env.DB.prepare("INSERT INTO otp_requests (id, identifier, code, purpose, expires_at) VALUES (?,?,?,?,?)")
          .bind(crypto.randomUUID(), body.email, otp, 'register', now + 300).run();
        return jsonOk({ message: "Registrasi sukses.", sim_otp: otp }); 
      } catch(e) { return jsonError("Gagal: Email/No HP sudah digunakan."); }
    }

    // Logika Verify OTP, Set PIN, dll... (Dipersingkat agar fokus pada sekuriti)
    // (Dalam script asli, letakkan logika verify-otp dan set-pin di sini seperti sebelumnya)
    if (action === "verify-otp") {
      const otpRow = await env.DB.prepare("SELECT * FROM otp_requests WHERE identifier=? AND code=? AND expires_at > ?").bind(body.identifier, body.otp, now).first();
      if(!otpRow) return jsonError("Kode OTP salah atau kadaluarsa.");
      await env.DB.prepare("DELETE FROM otp_requests WHERE id=?").bind(otpRow.id).run();
      if(otpRow.purpose === 'register') await env.DB.prepare("UPDATE users SET status='active' WHERE email=? OR phone=?").bind(body.identifier, body.identifier).run();
      return jsonOk({ message: "Verifikasi berhasil.", purpose: otpRow.purpose });
    }

    if (action === "set-pin") {
      const hashedPin = await hashData(body.pin);
      await env.DB.prepare("UPDATE users SET pin_hash=? WHERE email=? OR phone=?").bind(hashedPin, body.identifier, body.identifier).run();
      return jsonOk({ message: "PIN berhasil disimpan." });
    }

    return jsonError("Endpoint tidak valid.", 404);
  } catch(e) {
    return jsonError("Server Error", 500);
  }
}
