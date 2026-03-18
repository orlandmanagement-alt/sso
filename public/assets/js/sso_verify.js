import { getQueryParam, postJson, setNotice } from "./sso_core.js";

const form = document.getElementById("verifyOtpForm");
const emailEl = document.getElementById("email");
const otpEl = document.getElementById("otp");
const portalEl = document.getElementById("portal");
const nextEl = document.getElementById("next");

if(emailEl) emailEl.value = getQueryParam("email", "");
if(portalEl) portalEl.value = getQueryParam("portal", "");
if(nextEl) nextEl.value = getQueryParam("next", "/");

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setNotice("Memverifikasi OTP dan Kredensial Keamanan...");

  const payload = {
    email: String(emailEl?.value || "").trim(),
    otp: String(otpEl?.value || "").trim(),
    portal: String(portalEl?.value || "").trim(),
    next: String(nextEl?.value || "").trim() || "/"
  };

  const res = await postJson("/api/auth/verify_otp", payload);

  if(!res.ok){
    let msg = res?.data?.message || res?.data?.error || "Gagal memverifikasi OTP.";
    if(res.statusCode === 403 && msg.includes("locked")) {
      msg = "Akun terkunci sementara karena aktivitas mencurigakan. Coba lagi nanti.";
    }
    setNotice(msg, "error");
    return;
  }

  const redirectUrl = String(res?.data?.redirect_url || "").trim();
  setNotice("Otentikasi berhasil. Mengalihkan ke portal...", "success");

  setTimeout(() => { location.href = redirectUrl || "/index.html"; }, 400);
});
