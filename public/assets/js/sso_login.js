import { getQueryParam, postJson, setNotice } from "./sso_core.js";

const form = document.getElementById("requestOtpForm");
const emailEl = document.getElementById("email");
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
  setNotice("Requesting OTP...");

  const payload = {
    email: String(emailEl?.value || "").trim(),
    portal: String(portalEl?.value || "").trim(),
    next: String(nextEl?.value || "").trim() || "/"
  };

  const res = await postJson("/functions/api/auth/request_otp", payload);

  if(!res.ok){
    setNotice(res?.data?.message || "Failed to request OTP.", "error");
    return;
  }

  const url = new URL("/verify.html", location.origin);
  url.searchParams.set("email", payload.email);
  if(payload.portal) url.searchParams.set("portal", payload.portal);
  url.searchParams.set("next", payload.next);
  setNotice("OTP sent. Redirecting...", "success");
  setTimeout(() => { location.href = url.toString(); }, 500);
});
