async function getSetting(env, key, fallback = ""){
  const row = await env.DB.prepare(`
    SELECT v
    FROM auth_provider_settings
    WHERE k = ?
    LIMIT 1
  `).bind(String(key || "")).first();
  return row?.v != null ? String(row.v) : String(fallback);
}

async function postJson(url, body, headers = {}){
  const res = await fetch(url, {
    method: "POST",
    headers: Object.assign({
      "content-type": "application/json"
    }, headers),
    body: JSON.stringify(body)
  });

  let data = null;
  try { data = await res.json(); } catch {}

  if(!res.ok){
    const msg = data?.message || data?.error?.message || `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }

  return data;
}

export async function sendEmailOtp(env, { to, code, expiresSec = 300 }){
  const provider = await getSetting(env, "otp_email_provider", "resend");
  const from = await getSetting(env, "otp_email_from", "no-reply@orlandmanagement.com");

  if(provider === "disabled"){
    return { skipped: true, provider };
  }

  if(provider !== "resend"){
    throw new Error("email_provider_not_supported");
  }

  const apiKey = await getSetting(env, "otp_resend_api_key", "");
  if(!apiKey){
    throw new Error("resend_api_key_missing");
  }

  const subject = "Kode OTP Orland Management";
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5">
      <h2>Kode OTP Anda</h2>
      <p>Gunakan kode berikut untuk login:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:4px;margin:16px 0">${String(code || "")}</div>
      <p>Kode berlaku selama ${Number(expiresSec || 300)} detik.</p>
      <p>Jika Anda tidak meminta kode ini, abaikan email ini.</p>
    </div>
  `;

  return await postJson(
    "https://api.resend.com/emails",
    {
      from,
      to: [to],
      subject,
      html
    },
    {
      Authorization: `Bearer ${apiKey}`
    }
  );
}

export async function sendSmsOtp(env, { to, code }){
  const provider = await getSetting(env, "otp_sms_provider", "disabled");
  if(provider === "disabled"){
    return { skipped: true, provider };
  }
  throw new Error("sms_provider_not_supported_yet");
}

export async function sendWhatsappOtp(env, { to, code }){
  const provider = await getSetting(env, "otp_wa_provider", "disabled");
  if(provider === "disabled"){
    return { skipped: true, provider };
  }
  throw new Error("whatsapp_provider_not_supported_yet");
}

export async function sendOtpByChannel(env, { channel, identityType, identityValue, code, expiresSec }){
  const ch = String(channel || "").trim().toLowerCase();

  if(ch === "email"){
    return await sendEmailOtp(env, {
      to: identityValue,
      code,
      expiresSec
    });
  }

  if(ch === "sms"){
    return await sendSmsOtp(env, {
      to: identityValue,
      code
    });
  }

  if(ch === "whatsapp"){
    return await sendWhatsappOtp(env, {
      to: identityValue,
      code
    });
  }

  throw new Error("invalid_otp_channel");
}

export async function getOtpRuntimeConfig(env){
  const [defaultChannel, resendCooldownSec, expirySec] = await Promise.all([
    getSetting(env, "otp_default_channel", "email"),
    getSetting(env, "otp_resend_cooldown_sec", "30"),
    getSetting(env, "otp_expiry_sec", "300")
  ]);

  return {
    defaultChannel: String(defaultChannel || "email"),
    resendCooldownSec: Math.max(5, Number(resendCooldownSec || 30)),
    expirySec: Math.max(60, Number(expirySec || 300))
  };
}
