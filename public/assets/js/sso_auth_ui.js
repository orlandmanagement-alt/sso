const TURNSTILE_SITE_KEY = "0x4AAAAAACs8dTzAqMf1YwNJ";
const allViews = ['view-login', 'view-register', 'view-forgot', 'view-login-otp', 'view-check-email', 'view-login-pin', 'view-create-pin', 'view-social-role'];
let otpInterval;

window.enforceNumeric = function(input) { input.value = input.value.replace(/[^0-9]/g, ''); }
window.togglePw = function(inputId, icon) { const el = document.getElementById(inputId); if(el.type === "password") { el.type = "text"; icon.classList.replace("fa-eye-slash", "fa-eye"); } else { el.type = "password"; icon.classList.replace("fa-eye", "fa-eye-slash"); } }

window.showToast = function(message, type = 'success', duration = 4000) {
    const container = document.getElementById('toast-container'); if(!container) return;
    const toast = document.createElement('div');
    let icon = type === 'success' ? '<i class="fa-solid fa-circle-check text-green-500 text-xl"></i>' : type === 'error' ? '<i class="fa-solid fa-circle-xmark text-red-500 text-xl"></i>' : type === 'warning' ? '<i class="fa-solid fa-triangle-exclamation text-orange-500 text-xl"></i>' : '<i class="fa-solid fa-circle-info text-blue-500 text-xl"></i>';
    toast.className = `toast flex items-center ${type}`;
    toast.innerHTML = `${icon}<div class="text-sm font-medium text-gray-700">${message}</div>`;
    container.appendChild(toast); setTimeout(() => toast.classList.add('show'), 10); setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, duration);
}

window.showView = function(target) {
    allViews.forEach(v => document.getElementById(v)?.classList.add('hidden')); document.getElementById(target)?.classList.remove('hidden');
    if(window.innerWidth < 768 && target !== 'view-login' && target !== 'view-register') { document.getElementById('blue-panel')?.classList.add('hidden'); } else { document.getElementById('blue-panel')?.classList.remove('hidden'); }
}

window.switchMode = function(mode) {
    const mc = document.getElementById('main-container'), bp = document.getElementById('blue-panel'); bp?.classList.remove('hidden');
    if (mode === 'register') {
        if(window.innerWidth > 767) { mc?.classList.add('flex-row-reverse'); bp?.classList.add('reverse'); }
        document.getElementById('panel-content-login')?.classList.add('hidden'); document.getElementById('panel-content-register')?.classList.remove('hidden'); window.showView('view-register');
    } else {
        mc?.classList.remove('flex-row-reverse'); bp?.classList.remove('reverse');
        document.getElementById('panel-content-register')?.classList.add('hidden'); document.getElementById('panel-content-login')?.classList.remove('hidden'); window.showView('view-login');
    }
}

window.renderTurnstileWidgets = function() {
    if (!window.turnstile) return;
    ['turnstile-login', 'turnstile-register', 'turnstile-pin'].forEach(id => {
        const el = document.getElementById(id); if (el && !el.hasChildNodes()) window.turnstile.render(el, { sitekey: TURNSTILE_SITE_KEY, theme: 'light' });
    });
}
window.resetTurnstile = function() { if (window.turnstile) window.turnstile.reset(); }

async function sendApi(action, payload) {
    try { const res = await fetch(`/api/auth/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); return await res.json(); } 
    catch(e) { return { status: 'error', message: 'Gagal terhubung ke server.' }; }
}

function startOtpTimer() {
    clearInterval(otpInterval); let timeLeft = 30; const timerEl = document.getElementById('otp-timer'); const resendBtn = document.getElementById('btn-resend-otp');
    if(timerEl && resendBtn) {
        timerEl.parentElement.classList.remove('hidden'); resendBtn.classList.add('hidden'); timerEl.innerText = timeLeft;
        otpInterval = setInterval(() => { timeLeft--; timerEl.innerText = timeLeft; if(timeLeft <= 0) { clearInterval(otpInterval); timerEl.parentElement.classList.add('hidden'); resendBtn.classList.remove('hidden'); } }, 1000);
    }
}

// === LOGIN PASSWORD (DENGAN INTERCEPT UNVERIFIED) ===
window.handleRegularLogin = async function() {
    const ts = document.querySelector('#turnstile-login [name="cf-turnstile-response"]')?.value; if(!ts && window.turnstile) return window.showToast("Harap centang Captcha", "error");
    window.showToast("Memverifikasi...", "info");
    const res = await sendApi('login-password', { identifier: document.getElementById('login-id').value, password: document.getElementById('login-pass').value, turnstile_token: ts });
    window.resetTurnstile();
    
    if(res.status === 'ok') {
        // Cek jika butuh aktivasi
        if(res.needs_activation) {
            window.showToast(res.message, "warning", 6000);
            if(res.sim_otp) console.log("SIMULASI OTP (KARENA EMAIL GAGAL):", res.sim_otp);
            
            document.getElementById('otp-identifier').value = res.email;
            document.getElementById('otp-purpose').value = 'register';
            document.getElementById('blue-panel')?.classList.add('opacity-0', 'pointer-events-none');
            window.showView('view-check-email');
            startOtpTimer();
        } else {
            window.showToast("Login Berhasil!", "success");
            setTimeout(() => window.location.href = res.redirect_url, 1000);
        }
    } else window.showToast(res.message, "error");
}

// === REGISTER (DENGAN FALLBACK EMAIL GAGAL) ===
window.handleRegisterSubmit = async function() {
    const ts = document.querySelector('#turnstile-register [name="cf-turnstile-response"]')?.value; if(!ts && window.turnstile) return window.showToast("Harap centang Captcha", "error");
    if(document.getElementById('reg-pass').value.length < 8) return window.showToast("Password minimal 8 karakter", "error");
    
    const email = document.getElementById('reg-email').value;
    window.showToast("Mendaftarkan...", "info");
    const res = await sendApi('register', { fullName: document.getElementById('reg-user').value, email: email, phone: document.getElementById('reg-phone').value, password: document.getElementById('reg-pass').value, role: document.querySelector('input[name="reg-role"]:checked').value, turnstile_token: ts });
    window.resetTurnstile();
    
    if(res.status === 'ok') {
        window.showToast(res.message, res.sim_otp ? "warning" : "success", 5000);
        if(res.sim_otp) console.log("SIMULASI OTP (KARENA EMAIL GAGAL):", res.sim_otp); // Cek Console Log browser!
        
        document.getElementById('otp-identifier').value = email; document.getElementById('otp-purpose').value = 'register';
        document.getElementById('blue-panel')?.classList.add('opacity-0', 'pointer-events-none');
        window.showView('view-check-email');
        startOtpTimer();
    } else window.showToast(res.message, "error");
}

window.handlePinLogin = async function() {
    const ts = document.querySelector('#turnstile-pin [name="cf-turnstile-response"]')?.value; if(!ts && window.turnstile) return window.showToast("Harap centang Captcha", "error");
    window.showToast("Memverifikasi PIN...", "info");
    const res = await sendApi('login-pin', { identifier: document.getElementById('login-pin-id').value, pin: document.getElementById('login-pin-input').value, turnstile_token: ts }); window.resetTurnstile();
    if(res.status === 'ok') { window.showToast("Login Berhasil!", "success"); setTimeout(() => window.location.href = res.redirect_url, 1000); } else window.showToast(res.message, "error");
}

window.handleForgotSubmit = async function() {
    const id = document.getElementById('forgot-id').value; window.showToast("Meminta Token Reset...", "info");
    const res = await sendApi('request-otp', { identifier: id, purpose: 'reset' });
    if(res.status === 'ok') { window.showToast("Link Reset terkirim!", "success"); setTimeout(() => window.switchMode('login'), 2000); } else window.showToast(res.message, "error");
}

window.requestOtp = async function() {
    const id = document.getElementById('otp-id').value || document.getElementById('otp-identifier').value; window.showToast("Meminta OTP...", "info");
    const res = await sendApi('request-otp', { identifier: id, purpose: 'login' });
    if(res.status === 'ok') {
        window.showToast(res.message, "success");
        document.getElementById('otp-identifier').value = id; document.getElementById('otp-purpose').value = 'login';
        window.showView('view-check-email'); startOtpTimer();
    } else window.showToast(res.message, "error");
}

window.resendOtp = async function() {
    const id = document.getElementById('otp-identifier').value; const purp = document.getElementById('otp-purpose').value; window.showToast("Mengirim ulang...", "info");
    const res = await sendApi('request-otp', { identifier: id, purpose: purp });
    if(res.status === 'ok') { window.showToast("OTP terkirim ulang", "success"); if(res.sim_otp) console.log("OTP Simulasi:", res.sim_otp); startOtpTimer(); } else window.showToast(res.message, "error");
}

window.verifyOtp = async function() {
    const id = document.getElementById('otp-identifier').value; const purp = document.getElementById('otp-purpose').value; const code = document.getElementById('otp-code').value;
    const endpoint = purp === 'login' ? 'login-otp' : 'verify-otp'; window.showToast("Memverifikasi...", "info");
    const res = await sendApi(endpoint, { identifier: id, otp: code });
    if(res.status === 'ok') {
        if(purp === 'login') { window.showToast("Login OTP Sukses!", "success"); setTimeout(() => window.location.href = res.redirect_url, 1000); } 
        else { window.showToast("Akun Aktif! Buat PIN.", "success"); document.getElementById('pin-identifier').value = id; window.showView('view-create-pin'); }
    } else window.showToast(res.message, "error");
}

window.handleCreatePin = async function() {
    const p1 = document.getElementById('new-pin').value; if(p1.length < 6) return window.showToast("PIN harus 6 digit.", "error"); if(p1 !== document.getElementById('confirm-pin').value) return window.showToast("PIN tidak cocok.", "error");
    const res = await sendApi('set-pin', { identifier: document.getElementById('pin-identifier').value, pin: p1 });
    if(res.status === 'ok') { window.showToast("PIN Tersimpan! Mengalihkan...", "success"); setTimeout(() => window.location.href = res.redirect_url, 1500); } else window.showToast(res.message, "error");
}

// === GOOGLE & SOCIAL ===
window.handleGoogleLogin = async function(response) {
    window.showToast("Memverifikasi Google...", "success");
    const res = await sendApi('google-login', { credential: response.credential });
    if(res.status === 'ok') {
        if(res.is_new) { window.showToast("Pilih Role Anda.", "info"); document.getElementById('social-temp-token').value = res.temp_token; document.getElementById('blue-panel')?.classList.add('opacity-0', 'pointer-events-none'); window.showView('view-social-role'); } 
        else { window.showToast("Login Berhasil! Mengalihkan...", "success"); setTimeout(() => window.location.href = res.redirect_url, 1000); }
    } else window.showToast(res.message, "error");
}

window.processSocialRegistration = async function() {
    const role = document.querySelector('input[name="soc-role"]:checked').value; const temp = document.getElementById('social-temp-token').value;
    window.showToast("Menyimpan data...", "info");
    const res = await sendApi('social-complete', { temp_token: temp, role: role });
    if(res.status === 'ok') { window.showToast("Sukses! Mengalihkan...", "success"); setTimeout(() => window.location.href = res.redirect_url, 1000); } else window.showToast(res.message, "error");
}

document.addEventListener('DOMContentLoaded', () => { 
    setTimeout(window.renderTurnstileWidgets, 500); 
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('new_social') === 'true') {
        window.showToast("Terhubung. Pilih Role Anda.", "success");
        document.getElementById('social-temp-token').value = urlParams.get('temp_token');
        document.getElementById('social-provider-icon').className = urlParams.get('provider') === 'facebook' ? "fa-brands fa-facebook-f text-3xl text-blue-600" : "fa-brands fa-tiktok text-3xl text-black";
        document.getElementById('blue-panel')?.classList.add('opacity-0', 'pointer-events-none');
        window.showView('view-social-role');
        window.history.replaceState({}, document.title, window.location.pathname);
    }
});
window.addEventListener('resize', () => { if(!document.getElementById('view-register')?.classList.contains('hidden') && window.innerWidth > 767) { document.getElementById('main-container')?.classList.add('flex-row-reverse'); document.getElementById('blue-panel')?.classList.add('reverse'); } });
