import { postJson, getJson } from "./sso_core.js";

const API = {
  loginCheck: "/api/auth/login_check",
  loginPin: "/api/auth/login_pin",
  requestOtp: "/api/auth/request_otp",
  verifyOtp: "/api/auth/verify_otp",
  register: "/api/auth/register",
  registerFinalize: "/api/auth/register_finalize",
  requestReset: "/api/auth/request_password_reset",
  resetFinalize: "/api/auth/reset_pin_verify",
  resolveRedirect: "/api/auth/resolve_redirect"
};

function qs(sel) { return document.querySelector(sel); }
function qsa(sel) { return Array.from(document.querySelectorAll(sel)); }

function setNotice(message, type = "") {
  const el = qs("#notice");
  if (!el) return;
  el.className = `notice ${type}`.trim();
  el.textContent = message || "";
}

function activateTab(name) {
  qsa(".tab").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === name));
  qsa(".tabpanel").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === name));
  setNotice("");
}

function wireTabs() { qsa(".tab").forEach(btn => btn.addEventListener("click", () => activateTab(btn.dataset.tab))); }
function showSubForm(formIdToShow, groupSelector) {
  qsa(groupSelector).forEach(f => f.classList.add("hidden"));
  qs(formIdToShow)?.classList.remove("hidden");
}

async function resolveAndRedirect() {
  const res = await getJson(API.resolveRedirect);
  if (res.ok && res.data?.redirect_url) { location.href = res.data.redirect_url; return; }
  location.href = "https://dashboard.orlandmanagement.com";
}

function wireLoginFlow() {
  let loginContext = { identifier: "" };

  qs("#loginInitForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setNotice("Memeriksa akun...");
    loginContext.identifier = qs("#loginIdentifier").value.trim();
    
    const res = await postJson(API.loginCheck, { identifier: loginContext.identifier });
    if(!res.ok) return setNotice(res?.data?.message || "Akun tidak ditemukan.", "error");

    showSubForm("#loginPinForm", "#loginInitForm, #loginPinForm, #loginOtpForm");
    setNotice("Akun ditemukan. Masukkan PIN Anda.", "success");
  });

  qs("#loginPinForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setNotice("Memverifikasi PIN...");
    const payload = { identifier: loginContext.identifier, pin: qs("#loginPin").value.trim() };
    
    const res = await postJson(API.loginPin, payload);
    if(!res.ok) {
      let msg = res?.data?.message || "PIN salah.";
      if(res.statusCode === 403) msg = "Akun terkunci karena terlalu banyak percobaan gagal.";
      return setNotice(msg, "error");
    }
    
    setNotice("Login berhasil. Mengalihkan...", "success");
    await resolveAndRedirect();
  });

  qs("#btnUseOtpFallback")?.addEventListener("click", async (e) => {
    e.preventDefault();
    setNotice("Meminta OTP...");
    const res = await postJson(API.requestOtp, { identifier: loginContext.identifier, channel: "email" });
    if(!res.ok) return setNotice("Gagal mengirim OTP.", "error");

    showSubForm("#loginOtpForm", "#loginInitForm, #loginPinForm, #loginOtpForm");
    setNotice("OTP dikirim ke email/WA Anda.", "success");
  });

  qs("#loginOtpForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setNotice("Memverifikasi OTP...");
    const res = await postJson(API.verifyOtp, { identifier: loginContext.identifier, otp: qs("#loginOtpCode").value.trim() });
    if(!res.ok) return setNotice("OTP tidak valid.", "error");

    setNotice("Login berhasil. Mengalihkan...", "success");
    await resolveAndRedirect();
  });
}

function wireRegisterFlow() {
  let regContext = {};

  qs("#registerInitForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setNotice("Memproses data & mengirim OTP...");
    regContext = {
      role: qs("#registerRole").value,
      channel: qs("#registerOtpChannel").value,
      email: qs("#registerEmail").value.trim(),
      wa: qs("#registerWa").value.trim()
    };
    
    const res = await postJson(API.register, { role: regContext.role, otp_channel: regContext.channel, email: regContext.email, wa: regContext.wa });
    if(!res.ok) return setNotice(res?.data?.message || "Email/WA mungkin sudah terdaftar.", "error");

    showSubForm("#registerVerifyForm", "#registerInitForm, #registerVerifyForm, #registerPinForm");
    setNotice(`OTP berhasil dikirim via ${regContext.channel}.`, "success");
  });

  qs("#registerVerifyForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    regContext.otp = qs("#registerVerifyCode").value.trim();
    showSubForm("#registerPinForm", "#registerInitForm, #registerVerifyForm, #registerPinForm");
    setNotice("Kode disimpan. Silakan buat PIN 6-Digit Anda.", "success");
  });

  qs("#registerPinForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pin1 = qs("#registerPin1").value;
    const pin2 = qs("#registerPin2").value;
    if (pin1 !== pin2) return setNotice("Konfirmasi PIN tidak cocok!", "error");

    setNotice("Menyimpan PIN & Mengaktifkan akun...");
    regContext.pin = pin1;
    
    const res = await postJson(API.registerFinalize, regContext);
    if(!res.ok) return setNotice("Gagal memverifikasi akun.", "error");
    
    setNotice("Akun aktif! Silakan masuk.", "success");
    setTimeout(() => {
      activateTab("login");
      showSubForm("#loginInitForm", "#loginInitForm, #loginPinForm, #loginOtpForm");
      qs("#loginIdentifier").value = regContext.email;
    }, 1500);
  });
}

function wireResetFlow() {
  let resetCtx = {};

  qs("#resetRequestForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setNotice("Mengirim kode pemulihan...");
    resetCtx.identifier = qs("#resetIdentifier").value.trim();
    resetCtx.channel = qs("#resetChannel").value;
    
    const res = await postJson(API.requestReset, resetCtx);
    if(!res.ok) return setNotice("Gagal meminta kode.", "error");

    showSubForm("#resetVerifyForm", "#resetRequestForm, #resetVerifyForm, #resetPinForm");
    setNotice(`Kode pemulihan dikirim via ${resetCtx.channel}.`, "success");
  });

  qs("#resetVerifyForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    resetCtx.otp = qs("#resetOtpCode").value.trim();
    showSubForm("#resetPinForm", "#resetRequestForm, #resetVerifyForm, #resetPinForm");
    setNotice("Silakan buat PIN baru Anda.", "success");
  });

  qs("#resetPinForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setNotice("Memperbarui PIN...");
    resetCtx.pin = qs("#resetNewPin").value.trim();
    
    const res = await postJson(API.resetFinalize, resetCtx);
    if(!res.ok) return setNotice("Gagal memperbarui PIN.", "error");

    setNotice("PIN berhasil diperbarui. Silakan login.", "success");
    setTimeout(() => {
      activateTab("login");
      showSubForm("#loginInitForm", "#loginInitForm, #loginPinForm, #loginOtpForm");
    }, 1500);
  });
}

wireTabs(); wireLoginFlow(); wireRegisterFlow(); wireResetFlow();
