const TURNSTILE_SITE_KEY = "0x4AAAAAACs8dTzAqMf1YwNJ";
const allViews = ['view-login', 'view-register', 'view-forgot', 'view-login-otp', 'view-verify-otp', 'view-login-pin', 'view-check-email', 'view-create-pin', 'view-social-register'];
let otpInterval;

console.log("SSO UI Loaded: Path Corrected");

// Pastikan semua fungsi terpasang ke window (Global Scope) agar onclick di HTML bisa membacanya
window.enforceNumeric = function(input) { input.value = input.value.replace(/[^0-9]/g, ''); }

window.showToast = function(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    let icon = type === 'success' ? '<i class="fa-solid fa-circle-check text-green-500 text-xl"></i>' : '<i class="fa-solid fa-circle-info text-blue-500 text-xl"></i>';
    if(type === 'error') icon = '<i class="fa-solid fa-circle-xmark text-red-500 text-xl"></i>';
    toast.className = 'toast flex items-center w-72';
    toast.innerHTML = `${icon}<div class="text-sm font-medium text-gray-700">${message}</div>`;
    container.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 4000);
}

window.showView = function(target) {
    allViews.forEach(v => document.getElementById(v)?.classList.add('hidden'));
    document.getElementById(target)?.classList.remove('hidden');
    if(window.innerWidth < 768 && target !== 'view-login' && target !== 'view-register') {
        document.getElementById('blue-panel')?.classList.add('hidden');
    } else {
        document.getElementById('blue-panel')?.classList.remove('hidden');
    }
}

window.switchMode = function(mode) {
    const mc = document.getElementById('main-container'), bp = document.getElementById('blue-panel');
    bp?.classList.remove('hidden');
    if (mode === 'register') {
        if(window.innerWidth > 767) { mc?.classList.add('flex-row-reverse'); bp?.classList.add('reverse'); }
        document.getElementById('panel-content-login')?.classList.add('hidden');
        document.getElementById('panel-content-register')?.classList.remove('hidden');
        window.showView('view-register');
    } else {
        mc?.classList.remove('flex-row-reverse'); bp?.classList.remove('reverse');
        document.getElementById('panel-content-register')?.classList.add('hidden');
        document.getElementById('panel-content-login')?.classList.remove('hidden');
        window.showView('view-login');
    }
}

window.resetTurnstile = function() { if (window.turnstile) window.turnstile.reset(); }
window.renderTurnstileWidgets = function() {
    if (!window.turnstile) return;
    ['turnstile-login', 'turnstile-register', 'turnstile-pin', 'turnstile-social'].forEach(id => {
        const el = document.getElementById(id);
        if (el && !el.hasChildNodes()) window.turnstile.render(el, { sitekey: TURNSTILE_SITE_KEY, theme: 'light' });
    });
}

// Wrapper Fetch API internal
async function sendApi(action, payload) {
    try {
        const res = await fetch(`/api/auth/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        return await res.json();
    } catch(e) { return { status: 'error', message: 'Gagal terhubung ke server.' }; }
}

function startOtpTimer() {
    clearInterval(otpInterval);
    let timeLeft = 30;
    const timerEl = document.getElementById('otp-timer');
    const resendBtn = document.getElementById('btn-resend-otp');
    if(timerEl && resendBtn) {
        timerEl.parentElement.classList.remove('hidden');
        resendBtn.classList.add('hidden');
        timerEl.innerText = timeLeft;
        otpInterval = setInterval(() => {
            timeLeft--; timerEl.innerText = timeLeft;
            if(timeLeft <= 0) { clearInterval(otpInterval); timerEl.parentElement.classList.add('hidden'); resendBtn.classList.remove('hidden'); }
        }, 1000);
    }
}

// --- LOGIKA FORM ---

window.doLoginPassword = async function() {
    const ts = document.querySelector('#turnstile-login [name="cf-turnstile-response"]')?.value;
    if(!ts && window.turnstile) return window.showToast("Menunggu validasi keamanan Bot...", "error");
    window.showToast("Memverifikasi...", "success");
    const res = await sendApi('login-password', { identifier: document.getElementById('logId').value, password: document.getElementById('logPw').value, turnstile_token: ts });
    window.resetTurnstile();
    if(res.status === 'ok') {
        window.showToast("Login Sukses! Mengalihkan...", "success");
        setTimeout(() => window.location.href = res.redirect_url || "https://dashboard.orlandmanagement.com", 1500);
    } else window.showToast(res.message, "error");
}

window.doLoginPin = async function() {
    const ts = document.querySelector('#turnstile-pin [name="cf-turnstile-response"]')?.value;
    if(!ts && window.turnstile) return window.showToast("Menunggu validasi keamanan Bot...", "error");
    window.showToast("Memverifikasi PIN...", "success");
    const res = await sendApi('login-pin', { identifier: document.getElementById('logPinId').value, pin: document.getElementById('logPinCode').value, turnstile_token: ts });
    window.resetTurnstile();
    if(res.status === 'ok') {
        window.showToast("Login Sukses! Mengalihkan...", "success");
        setTimeout(() => window.location.href = res.redirect_url || "https://dashboard.orlandmanagement.com", 1500);
    } else window.showToast(res.message, "error");
}

window.handleRegisterSubmit = async function() {
    const ts = document.querySelector('#turnstile-register [name="cf-turnstile-response"]')?.value;
    if(!ts && window.turnstile) return window.showToast("Menunggu validasi keamanan Bot...", "error");
    const email = document.getElementById('reg-email').value;
    window.showToast("Mendaftarkan akun...", "info");
    const res = await sendApi('register', {
        fullName: document.getElementById('reg-name').value, email: email, phone: document.getElementById('reg-phone').value,
        password: document.getElementById('reg-password').value, role: document.querySelector('input[name="role"]:checked').value, turnstile_token: ts
    });
    window.resetTurnstile();
    if(res.status === 'ok') {
        window.showToast(res.message, "success");
        document.getElementById('otp-identifier').value = email;
        document.getElementById('otp-purpose').value = "register";
        window.showView('view-verify-otp');
        startOtpTimer();
    } else window.showToast(res.message, "error");
}

window.handleForgotSubmit = async function() {
    const id = document.getElementById('forgot-id').value;
    window.showToast("Meminta tautan/OTP...", "info");
    const res = await sendApi('request-otp', { identifier: id, purpose: 'reset' });
    if(res.status === 'ok') {
        window.showToast(res.message, "success");
        document.getElementById('otp-identifier').value = id;
        document.getElementById('otp-purpose').value = "reset";
        window.showView('view-verify-otp');
        startOtpTimer();
    } else window.showToast(res.message, "error");
}

window.requestLoginOtp = async function() {
    const id = document.getElementById('req-otp-id').value;
    window.showToast("Meminta OTP...", "info");
    const res = await sendApi('request-otp', { identifier: id, purpose: 'login' });
    if(res.status === 'ok') {
        window.showToast(res.message, "success");
        document.getElementById('otp-identifier').value = id;
        document.getElementById('otp-purpose').value = "login";
        window.showView('view-verify-otp');
        startOtpTimer();
    } else window.showToast(res.message, "error");
}

window.resendOtp = async function() {
    const id = document.getElementById('otp-identifier').value;
    const purp = document.getElementById('otp-purpose').value;
    window.showToast("Mengirim ulang OTP...", "info");
    const res = await sendApi('request-otp', { identifier: id, purpose: purp });
    if(res.status === 'ok') { window.showToast("OTP terkirim ulang", "success"); startOtpTimer(); }
    else window.showToast(res.message, "error");
}

window.verifyOtp = async function() {
    const id = document.getElementById('otp-identifier').value;
    const purp = document.getElementById('otp-purpose').value;
    const code = document.getElementById('otp-code').value;
    const endpoint = purp === 'login' ? 'login-otp' : 'verify-otp';
    
    const res = await sendApi(endpoint, { identifier: id, otp: code });
    if(res.status === 'ok') {
        clearInterval(otpInterval);
        if(purp === 'login') {
            window.showToast("Login OTP Sukses!", "success");
            setTimeout(() => window.location.href = res.redirect_url || "https://dashboard.orlandmanagement.com", 1500);
        } else {
            window.showToast("Verifikasi sukses! Silakan buat PIN.", "success");
            document.getElementById('pin-identifier').value = id;
            window.showView('view-create-pin');
        }
    } else window.showToast(res.message, "error");
}

window.handleCreatePin = async function() {
    const p1 = document.getElementById('new-pin').value;
    if(p1.length < 6) return window.showToast("PIN harus 6 digit.", "error");
    if(p1 !== document.getElementById('confirm-pin').value) return window.showToast("PIN tidak cocok.", "error");
    const res = await sendApi('set-pin', { identifier: document.getElementById('pin-identifier').value, pin: p1 });
    if(res.status === 'ok') {
        window.showToast("PIN Tersimpan! Silakan Login.", "success");
        window.switchMode('login');
    } else window.showToast(res.message, "error");
}

window.doSocialLogin = async function(provider) {
    window.showToast(`Menghubungkan ke ${provider}...`, "info");
    const res = await sendApi('social-check', { provider: provider });
    if (res.exists) {
        window.showToast("Login Sosial Sukses!", "success");
        setTimeout(() => window.location.href = "https://dashboard.orlandmanagement.com", 1500);
    } else {
        window.showToast(`Akun belum terdaftar. Silakan lengkapi.`, "info");
        document.getElementById('soc-name').value = res.data.name;
        document.getElementById('soc-email').value = res.data.email;
        document.getElementById('social-reg-icon').className = provider === 'Google' ? "fa-brands fa-google text-3xl text-red-500" : "fa-brands fa-facebook-f text-3xl text-blue-600";
        window.showView('view-social-register');
    }
}

window.handleSocialRegisterSubmit = async function() {
    const ts = document.querySelector('#turnstile-social [name="cf-turnstile-response"]')?.value;
    if(!ts && window.turnstile) return window.showToast("Menunggu validasi keamanan Bot...", "error");
    const email = document.getElementById('soc-email').value;
    const res = await sendApi('social-register', {
        fullName: document.getElementById('soc-name').value, email: email, phone: document.getElementById('soc-phone').value,
        password: document.getElementById('soc-password').value, role: 'talent', turnstile_token: ts
    });
    window.resetTurnstile();
    if(res.status === 'ok') {
        window.showToast(res.message, "success");
        document.getElementById('pin-identifier').value = email;
        window.showView('view-create-pin');
    } else window.showToast(res.message, "error");
}

// Inisialisasi Event Listener
document.addEventListener('DOMContentLoaded', () => { setTimeout(window.renderTurnstileWidgets, 500); });
window.addEventListener('resize', () => {
    if(!document.getElementById('view-register')?.classList.contains('hidden') && window.innerWidth > 767) {
        document.getElementById('main-container')?.classList.add('flex-row-reverse');
        document.getElementById('blue-panel')?.classList.add('reverse');
    }
});
