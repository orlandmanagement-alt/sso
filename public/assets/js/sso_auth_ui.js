const TURNSTILE_SITE_KEY = "0x4AAAAAACs8dTzAqMf1YwNJ";
const allViews = ['view-login', 'view-register', 'view-forgot', 'view-login-otp', 'view-verify-otp', 'view-login-pin', 'view-check-email', 'view-create-pin', 'view-social-register'];

// Fitur Toggle Visibility (Ikon Mata)
window.toggleVis = function(inputId, icon) {
    const el = document.getElementById(inputId);
    if(el.type === "password") { el.type = "text"; icon.classList.replace("fa-eye-slash", "fa-eye"); }
    else { el.type = "password"; icon.classList.replace("fa-eye", "fa-eye-slash"); }
}

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
    ['turnstile-login', 'turnstile-register', 'turnstile-pin'].forEach(id => {
        const el = document.getElementById(id);
        if (el && !el.hasChildNodes()) window.turnstile.render(el, { sitekey: TURNSTILE_SITE_KEY, theme: 'light' });
    });
}

async function sendApi(action, payload) {
    try {
        const res = await fetch(`/api/auth/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        return await res.json();
    } catch(e) { return { status: 'error', message: 'Gagal terhubung ke server SSO.' }; }
}

// === CALLBACK GOOGLE LOGIN ===
window.handleGoogleLogin = async function(response) {
    window.showToast("Memproses data Google...", "info");
    const res = await sendApi('google-login', { credential: response.credential });
    if(res.status === 'ok') {
        window.showToast("Login Sukses!", "success");
        setTimeout(() => window.location.href = res.redirect_url || "https://dashboard.orlandmanagement.com", 1500);
    } else window.showToast(res.message, "error");
}

window.doLoginPassword = async function() {
    const ts = document.querySelector('#turnstile-login [name="cf-turnstile-response"]')?.value;
    if(!ts && window.turnstile) return window.showToast("Menunggu validasi keamanan Bot...", "error");
    window.showToast("Memverifikasi kredensial...", "success");
    const res = await sendApi('login-password', { identifier: document.getElementById('logId').value, password: document.getElementById('logPw').value, turnstile_token: ts });
    window.resetTurnstile();
    if(res.status === 'ok') {
        window.showToast("Login Sukses!", "success");
        setTimeout(() => window.location.href = res.redirect_url, 1500);
    } else window.showToast(res.message, "error");
}

window.handleRegisterSubmit = async function() {
    const ts = document.querySelector('#turnstile-register [name="cf-turnstile-response"]')?.value;
    if(!ts && window.turnstile) return window.showToast("Menunggu validasi Bot...", "error");
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
    } else window.showToast(res.message, "error");
}

document.addEventListener('DOMContentLoaded', () => { setTimeout(window.renderTurnstileWidgets, 500); });
