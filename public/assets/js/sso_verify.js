import { getQueryParam, postJson, setNotice } from "./sso_core.js";

const form = document.getElementById("verifyOtpForm");
const emailEl = document.getElementById("email");
const otpEl = document.getElementById("otp");
const portalEl = document.getElementById("portal");
const nextEl = document.getElementById("next");

if(emailEl){
  emailEl.value = getQueryParam("email", "");
}
if(portalEl){
  portalEl.value = getQueryParam("portal", "");
}
if(nextEl){
  nextEl.value = getQueryParam("next", "/");
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setNotice("Verifying OTP...");

  const payload = {
    email: String(emailEl?.value || "").trim(),
    otp: String(otpEl?.value || "").trim(),
    portal: String(portalEl?.value || "").trim(),
    next: String(nextEl?.value || "").trim() || "/"
  };

  const res = await postJson("/functions/api/auth/verify_otp", payload);

  if(!res.ok){
    setNotice(res?.data?.message || "Failed to verify OTP.", "error");
    return;
  }

  const redirectUrl = String(res?.data?.redirect_url || "").trim();
  setNotice("OTP verified. Redirecting...", "success");

  if(redirectUrl){
    setTimeout(() => { location.href = redirectUrl; }, 400);
    return;
  }

  setTimeout(() => { location.href = "/index.html"; }, 400);
});
