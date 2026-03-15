import { jsonOk, jsonInvalid, jsonUnauthorized, jsonError } from "../../_core/response.js";

const KEYS = [
  "otp_default_channel",
  "otp_resend_cooldown_sec",
  "otp_expiry_sec",
  "otp_email_provider",
  "otp_email_from",
  "otp_resend_api_key",
  "otp_sms_provider",
  "otp_sms_api_key",
  "otp_sms_sender",
  "otp_wa_provider",
  "otp_wa_api_key",
  "otp_wa_sender"
];

const DEFAULTS = {
  otp_default_channel: "email",
  otp_resend_cooldown_sec: "30",
  otp_expiry_sec: "300",
  otp_email_provider: "resend",
  otp_email_from: "no-reply@orlandmanagement.com",
  otp_resend_api_key: "",
  otp_sms_provider: "disabled",
  otp_sms_api_key: "",
  otp_sms_sender: "ORLAND",
  otp_wa_provider: "disabled",
  otp_wa_api_key: "",
  otp_wa_sender: ""
};

function norm(v){
  return String(v ?? "").trim();
}

function bearerToken(request){
  const h = request.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? String(m[1] || "").trim() : "";
}

function normalize(body = {}){
  const out = {};
  for(const k of KEYS){
    out[k] = norm(body[k] ?? DEFAULTS[k]);
  }

  out.otp_default_channel = ["email","sms","whatsapp"].includes(out.otp_default_channel.toLowerCase())
    ? out.otp_default_channel.toLowerCase()
    : "email";

  out.otp_email_provider = ["resend","disabled"].includes(out.otp_email_provider.toLowerCase())
    ? out.otp_email_provider.toLowerCase()
    : "resend";

  out.otp_sms_provider = ["disabled","twilio","vonage"].includes(out.otp_sms_provider.toLowerCase())
    ? out.otp_sms_provider.toLowerCase()
    : "disabled";

  out.otp_wa_provider = ["disabled","twilio","wablas","fonnte"].includes(out.otp_wa_provider.toLowerCase())
    ? out.otp_wa_provider.toLowerCase()
    : "disabled";

  out.otp_resend_cooldown_sec = String(Math.max(5, Math.min(600, Number(out.otp_resend_cooldown_sec || 30))));
  out.otp_expiry_sec = String(Math.max(60, Math.min(1800, Number(out.otp_expiry_sec || 300))));

  return out;
}

async function ensureTable(env){
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS auth_provider_settings (
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `).run();
}

export async function onRequestPost({ request, env }){
  const expected = norm(env.INTERNAL_SYNC_TOKEN);
  const got = bearerToken(request);

  if(!expected || !got || got !== expected){
    return jsonUnauthorized("unauthorized_internal_sync");
  }

  let body;
  try{
    body = await request.json();
  }catch{
    return jsonInvalid("invalid_json");
  }

  try{
    await ensureTable(env);

    const clean = normalize(body || {});
    const ts = Math.floor(Date.now() / 1000);

    for(const k of KEYS){
      await env.DB.prepare(`
        INSERT INTO auth_provider_settings (k, v, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(k) DO UPDATE SET
          v=excluded.v,
          updated_at=excluded.updated_at
      `).bind(k, clean[k], ts).run();
    }

    return jsonOk({
      synced: true,
      updated_at: ts
    });
  }catch(err){
    return jsonError("sync_otp_settings_failed", {
      message: String(err?.message || err)
    });
  }
}
