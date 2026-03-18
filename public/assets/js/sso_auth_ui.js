import { apiCall, showToast } from "./sso_core.js";

const allViews = ['view-login', 'view-register', 'view-create-pin', 'view-verify-otp', 'view-login-pin', 'view-forgot', 'view-social-reg'];
let activeId = ""; 
let activePurpose = "";

// Ekspos fungsi ke global window agar bisa dipanggil dari atribut onclick di HTML
window.showView = function(target) {
    if(target === 'view-login-otp') { target = 'view-forgot'; document.getElementById('reqTitle').innerText = "Login via OTP"; activePurpose = "login"; }
    else if(target === 'view-forgot') { document.getElementById('reqTitle').innerText = "Lupa Password?"; activePurpose = "reset"; }
    allViews.forEach(v => document.getElementById(v).classList.add('hidden'));
    document.getElementById(target).classList.remove('hidden');
}

window.switchMode = function(mode) {
    const mc = document.getElementById('main-container'), bp = document.getElementById('blue-panel');
    if(mode === 'register') {
        if(window.innerWidth > 767) { mc.classList.add('flex-row-reverse'); bp.classList.add('reverse'); }
        document.getElementById('panel-content-login').classList.add('hidden'); 
        document.getElementById('panel-content-register').classList.remove('hidden');
        window.showView('view-register');
    } else {
        mc.classList.remove('flex-row-reverse'); bp.classList.remove('reverse');
        document.getElementById('panel-content-register').classList.add('hidden'); 
        document.getElementById('panel-content-login').classList.remove('hidden');
        window.showView('view-login');
    }
}

window.togglePw = function(inputId, icon) {
    const el = document.getElementById(inputId);
    if(el.type === "password") { el.type = "text"; icon.classList.replace("fa-eye-slash", "fa-eye"); }
    else { el.type = "password"; icon.classList.replace("fa-eye", "fa-eye-slash"); }
}

window.enforceNum = function(i) { i.value = i.value.replace(/[^0-9]/g, ''); }

window.doLoginPassword = async function() {
    showToast("Memverifikasi...", "success");
    const res = await apiCall('login', { identifier: document.getElementById('logId').value, password: document.getElementById('logPw').value });
    if(res.status === 'ok') { 
        showToast("Login Sukses! Mengalihkan...", "success"); 
        setTimeout(() => window.location.href = res.redirect_url || "https://dashboard.orlandmanagement.com", 1000); 
    } else showToast(res.message, "error");
}

window.doLoginPin = async function() {
    showToast("Memverifikasi PIN...", "success");
    const res = await apiCall('login', { identifier: document.getElementById('logPinId').value, pin: document.getElementById('logPinCode').value });
    if(res.status === 'ok') { 
        showToast("Login Sukses! Mengalihkan...", "success"); 
        setTimeout(() => window.location.href = res.redirect_url || "https://dashboard.orlandmanagement.com", 1000); 
    } else showToast(res.message, "error");
}

// Tambahkan sisa fungsionalitas register, request otp, verify otp, dsb. (Sama seperti logika inline sebelumnya namun rapi di sini).
