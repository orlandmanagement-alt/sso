import { jsonOk, jsonInvalid, jsonConflict, jsonError } from "../../_core/response.js";
import { sendOtpByChannel, getOtpRuntimeConfig } from "../../_core/otp_providers.js";

function norm(value){
  return String(value || "").trim();
}

function isEmail(value){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function isPhone(value){
  const v = String(value || "").replace(/[^\d]/g, "");
  return v.startsWith("62") || v.startsWith("08");
}

function makeId(prefix){
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeOtp(){
  return String(Math.floor(100000 + Math.random() * 900000));
}

function normalizePhone(value){
  const raw = String(value || "").replace(/[^\d]/g, "");
  if(raw.startsWith("62")) return raw;
  if(raw.startsWith("08")) return `62${raw.slice(1)}`;
  return raw;
}

function getClientIp(request){
  return request.headers.get("cf-connecting-ip") || "";
}

function getUserAgent(request){
  return request.headers.get("user-agent") || "";
}

async function sha256Hex(input){
  const data = new TextEncoder().encode(String(input || ""));
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function hashOtp(identityType, identityValue, code){
  return await sha256Hex(`otp|${identityType}|${identityValue}|${code}`);
}

async function createRiskFlag(env, payload){
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(`
    INSERT INTO security_risk_flags (
      id,
      user_id,
      risk_type,
      severity,
      payload_json,
      status,
      created_at
    ) VALUES (?, ?, ?, ?, ?, 'open', ?)
  `).bind(
    `rsk_${crypto.randomUUID()}`,
    payload.user_id || null,
    payload.risk_type,
    payload.severity,
    JSON.stringify(payload.payload || {}),
    now
  ).run();
}

export async function onRequestPost({ request, env }){
  let body;
  try{
    body = await request.json();
  }catch{
    return jsonInvalid("invalid_json");
  }

  const email = norm(body?.email).toLowerCase();
  const phone = normalizePhone(body?.phone || "");
  const requestedChannel = norm(body?.channel).toLowerCase();

  const hasEmail = !!email;
  const hasPhone = !!phone;

  if(!hasEmail && !hasPhone){
    return jsonInvalid("email_or_phone_required");
  }

  if(hasEmail && !isEmail(email)){
    return jsonInvalid("invalid_email");
  }

  if(hasPhone && !isPhone(phone)){
    return jsonInvalid("invalid_phone");
  }

  try{
    const cfg = await getOtpRuntimeConfig(env);

    const identityType = hasEmail ? "email" : "phone";
    const identityValue = hasEmail ? email : phone;

    let channel = requestedChannel || cfg.defaultChannel;

    if(identityType === "email"){
      channel = "email";
    } else if(identityType === "phone" && !channel){
      channel = "whatsapp";
    }

    if(!["email","sms","whatsapp"].includes(channel)){
      return jsonInvalid("invalid_channel");
    }

    if(channel === "email" && identityType !== "email"){
      return jsonInvalid("email_channel_requires_email");
    }

    if((channel === "sms" || channel === "whatsapp") && identityType !== "phone"){
      return jsonInvalid("phone_channel_requires_phone");
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + cfg.expirySec;
    const ipAddress = getClientIp(request);
    const userAgent = getUserAgent(request);

    const recentPending = await env.DB.prepare(`
      SELECT id, created_at, expires_at
      FROM auth_otp_challenges
      WHERE identity_type = ?
        AND identity_value = ?
        AND status = 'pending'
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(identityType, identityValue).first();

    if(recentPending){
      const age = now - Number(recentPending.created_at || 0);
      if(age < cfg.resendCooldownSec){
        return jsonConflict("otp_resend_cooldown", {
          challenge_id: recentPending.id,
          retry_after_sec: cfg.resendCooldownSec - age
        });
      }

      if(Number(recentPending.expires_at || 0) > now){
        await env.DB.prepare(`
          UPDATE auth_otp_challenges
          SET status = 'expired',
              updated_at = ?
          WHERE id = ?
        `).bind(now, recentPending.id).run();
      }
    }

    const recentFailures = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM auth_login_events
      WHERE identity_type = ?
        AND identity_value = ?
        AND success_flag = 0
        AND created_at >= ?
    `).bind(identityType, identityValue, now - 600).first();

    if(Number(recentFailures?.total || 0) >= 8){
      await createRiskFlag(env, {
        risk_type: "otp_abuse",
        severity: "high",
        payload: {
          identity_type: identityType,
          identity_value: identityValue,
          ip_address: ipAddress
        }
      });
    }

    const code = makeOtp();
    const codeHash = await hashOtp(identityType, identityValue, code);
    const challengeId = makeId("otp");

    await env.DB.prepare(`
      INSERT INTO auth_otp_challenges (
        id,
        identity_type,
        identity_value,
        code,
        code_hash,
        status,
        expires_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
    `).bind(
      challengeId,
      identityType,
      identityValue,
      code,
      codeHash,
      expiresAt,
      now,
      now
    ).run();

    try{
      await sendOtpByChannel(env, {
        channel,
        identityType,
        identityValue,
        code,
        expiresSec: cfg.expirySec
      });
    }catch(sendErr){
      await env.DB.prepare(`
        UPDATE auth_otp_challenges
        SET status = 'failed',
            updated_at = ?
        WHERE id = ?
      `).bind(now, challengeId).run();

      return jsonError("otp_delivery_failed", {
        channel,
        message: String(sendErr?.message || sendErr)
      });
    }

    await env.DB.prepare(`
      INSERT INTO auth_login_events (
        id,
        user_id,
        identity_type,
        identity_value,
        ip_address,
        user_agent,
        success_flag,
        reason,
        created_at
      ) VALUES (?, NULL, ?, ?, ?, ?, 0, 'otp_requested', ?)
    `).bind(
      `lge_${crypto.randomUUID()}`,
      identityType,
      identityValue,
      ipAddress,
      userAgent,
      now
    ).run();

    return jsonOk({
      challenge_id: challengeId,
      identity_type: identityType,
      channel,
      expires_at: expiresAt,
      resend_after_sec: cfg.resendCooldownSec
    });
  } catch(err){
    return jsonError("request_otp_failed", {
      message: String(err?.message || err)
    });
  }
}
