import { getQueryParam, postJson, setNotice } from "./sso_core.js";

const form = document.getElementById("requestOtpForm");
const emailEl = document.getElementById("email");
const portalEl = document.getElementById("portal");
const nextEl = document.getElementById("next");

if(emailEl) emailEl.value = getQueryParam("email", "");
if(portalEl) portalEl.value = getQueryParam("portal", "");
if(nextEl) nextEl.value = getQueryParam("next", "/");

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setNotice("Meminta OTP...");

  const payload = {
    email: String(emailEl?.value || "").trim(),
    portal: String(portalEl?.value || "").trim(),
    next: String(nextEl?.value || "").trim() || "/"
  };

  const res = await postJson("/api/auth/request_otp", payload);

  if(!res.ok){
    let msg = res?.data?.message || res?.data?.error || "Gagal meminta OTP.";
    setNotice(msg, "error");
    return;
  }

  const url = new URL("/verify.html", location.origin);
  url.searchParams.set("email", payload.email);
  if(payload.portal) url.searchParams.set("portal", payload.portal);
  url.searchParams.set("next", payload.next);
  
  setNotice("OTP berhasil dikirim. Mengalihkan...", "success");
  setTimeout(() => { location.href = url.toString(); }, 500);
});
