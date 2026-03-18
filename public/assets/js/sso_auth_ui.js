const API = {
  loginPassword: "/functions/api/auth/login_password",
  requestOtp: "/functions/api/auth/request_otp",
  verifyOtp: "/functions/api/auth/verify_otp",
  register: "/functions/api/auth/register",
  requestPasswordReset: "/functions/api/auth/request_password_reset",
  resetPasswordVerify: "/functions/api/auth/reset_password_verify",
  resolveRedirect: "/functions/api/auth/resolve_redirect"
};

function qs(sel){
  return document.querySelector(sel);
}

function qsa(sel){
  return Array.from(document.querySelectorAll(sel));
}

function setNotice(message, type = ""){
  const el = qs("#notice");
  if(!el) return;
  el.className = `notice ${type}`.trim();
  el.textContent = message || "";
}

async function parseJsonSafe(res){
  const text = await res.text();
  try{
    return JSON.parse(text);
  }catch{
    return {
      status: "error",
      data: {
        message: "invalid_server_response",
        raw: text
      }
    };
  }
}

async function postJson(url, body){
  const res = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {})
  });

  const json = await parseJsonSafe(res);

  return {
    ok: res.ok && json?.status === "ok",
    statusCode: res.status,
    status: json?.status || "error",
    data: json?.data || null,
    raw: json
  };
}

async function getJson(url){
  const res = await fetch(url, {
    method: "GET",
    credentials: "include"
  });

  const json = await parseJsonSafe(res);

  return {
    ok: res.ok && json?.status === "ok",
    statusCode: res.status,
    status: json?.status || "error",
    data: json?.data || null,
    raw: json
  };
}

function activateTab(name){
  qsa(".tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
  qsa(".tabpanel").forEach(panel => {
    panel.classList.toggle("active", panel.dataset.panel === name);
  });
  setNotice("");
}

function wireTabs(){
  qsa(".tab").forEach(btn => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });
}

async function resolveAndRedirect(){
  const res = await getJson(API.resolveRedirect);
  if(res.ok && res.data?.redirect_url){
    location.href = res.data.redirect_url;
    return;
  }
  location.href = "https://dashboard.orlandmanagement.com";
}

function wireLoginPassword(){
  qs("#loginPasswordForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Signing in...");

    const payload = {
      email: String(qs("#loginEmail")?.value || "").trim(),
      password: String(qs("#loginPassword")?.value || "").trim()
    };

    const res = await postJson(API.loginPassword, payload);

    if(!res.ok){
      setNotice(res?.data?.message || "Login failed.", "error");
      return;
    }

    setNotice("Login successful. Redirecting...", "success");
    await resolveAndRedirect();
  });
}

function wireOtpLogin(){
  qs("#requestOtpForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Requesting OTP...");

    const identifier = String(qs("#otpIdentifier")?.value || "").trim();
    const channel = String(qs("#otpChannel")?.value || "email").trim();

    const res = await postJson(API.requestOtp, {
      identifier,
      channel
    });

    if(!res.ok){
      setNotice(res?.data?.message || "Failed to request OTP.", "error");
      return;
    }

    const verifyIdentifier = qs("#verifyIdentifier");
    if(verifyIdentifier) verifyIdentifier.value = identifier;

    qs("#verifyOtpForm")?.classList.remove("hidden");
    setNotice(`OTP sent via ${channel}. Enter the code to continue.`, "success");
  });

  qs("#verifyOtpForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Verifying OTP...");

    const payload = {
      identifier: String(qs("#verifyIdentifier")?.value || "").trim(),
      otp: String(qs("#verifyOtpCode")?.value || "").trim()
    };

    const res = await postJson(API.verifyOtp, payload);

    if(!res.ok){
      setNotice(res?.data?.message || "OTP verification failed.", "error");
      return;
    }

    setNotice("Login successful. Redirecting...", "success");
    if(res.data?.redirect_url){
      location.href = res.data.redirect_url;
      return;
    }
    await resolveAndRedirect();
  });
}

function wireRegister(){
  let registerContext = {
    role: "",
    email: "",
    wa: "",
    channel: ""
  };

  qs("#registerForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Creating account...");

    registerContext = {
      role: String(qs("#registerRole")?.value || "talent").trim(),
      email: String(qs("#registerEmail")?.value || "").trim(),
      wa: String(qs("#registerWa")?.value || "").trim(),
      password: String(qs("#registerPassword")?.value || "").trim(),
      channel: String(qs("#registerOtpChannel")?.value || "email").trim()
    };

    const res = await postJson(API.register, {
      role: registerContext.role,
      email: registerContext.email,
      wa: registerContext.wa,
      password: registerContext.password,
      otp_channel: registerContext.channel
    });

    if(!res.ok){
      setNotice(res?.data?.message || "Registration failed.", "error");
      return;
    }

    qs("#registerVerifyForm")?.classList.remove("hidden");
    setNotice(`Account created. Verification code sent via ${registerContext.channel}.`, "success");
  });

  qs("#registerVerifyForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Verifying account...");

    const res = await postJson(API.verifyOtp, {
      identifier: registerContext.channel === "wa" ? registerContext.wa : registerContext.email,
      otp: String(qs("#registerVerifyCode")?.value || "").trim()
    });

    if(!res.ok){
      setNotice(res?.data?.message || "Verification failed.", "error");
      return;
    }

    setNotice("Account verified. Redirecting...", "success");
    if(res.data?.redirect_url){
      location.href = res.data.redirect_url;
      return;
    }
    await resolveAndRedirect();
  });
}

function wireResetPassword(){
  let resetContext = {
    identifier: "",
    channel: ""
  };

  qs("#resetRequestForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Requesting reset code...");

    resetContext = {
      identifier: String(qs("#resetIdentifier")?.value || "").trim(),
      channel: String(qs("#resetChannel")?.value || "email").trim()
    };

    const res = await postJson(API.requestPasswordReset, resetContext);

    if(!res.ok){
      setNotice(res?.data?.message || "Failed to request reset code.", "error");
      return;
    }

    qs("#resetVerifyForm")?.classList.remove("hidden");
    setNotice(`Reset code sent via ${resetContext.channel}.`, "success");
  });

  qs("#resetVerifyForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setNotice("Resetting password...");

    const res = await postJson(API.resetPasswordVerify, {
      identifier: resetContext.identifier,
      otp: String(qs("#resetOtpCode")?.value || "").trim(),
      new_password: String(qs("#resetNewPassword")?.value || "").trim()
    });

    if(!res.ok){
      setNotice(res?.data?.message || "Password reset failed.", "error");
      return;
    }

    setNotice("Password updated. You can login now.", "success");
    activateTab("login-password");
  });
}

wireTabs();
wireLoginPassword();
wireOtpLogin();
wireRegister();
wireResetPassword();
