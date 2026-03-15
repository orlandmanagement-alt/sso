import { jsonOk, jsonInvalid, jsonForbidden, jsonError } from "../../_core/response.js";
import { buildSessionCookie, hashSessionToken } from "../../_core/auth.js";

function norm(value){
  return String(value || "").trim();
}

function isEmail(value){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function normalizePhone(value){
  const raw = String(value || "").replace(/[^\d]/g, "");
  if(raw.startsWith("62")) return raw;
  if(raw.startsWith("08")) return `62${raw.slice(1)}`;
  return raw;
}

function makeId(prefix){
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeSessionToken(){
  return crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
}

function getClientIp(request){
  return request.headers.get("cf-connecting-ip") || "";
}

function getUserAgent(request){
  return request.headers.get("user-agent") || "";
}

function makeFingerprint(request, userId){
  const ua = getUserAgent(request);
  const ip = getClientIp(request);
  return btoa(`${userId}|${ua}|${ip}`).slice(0, 80);
}

async function sha256Hex(input){
  const data = new TextEncoder().encode(String(input || ""));
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function hashOtp(identityType, identityValue, code){
  return await sha256Hex(`otp|${identityType}|${identityValue}|${code}`);
}

async function ensureRole(env, userId, roleName, now){
  const role = await env.DB.prepare(`
    SELECT id, name
    FROM auth_roles
    WHERE name = ?
    LIMIT 1
  `).bind(roleName).first();

  if(!role) return;

  await env.DB.prepare(`
    INSERT OR IGNORE INTO auth_user_roles (
      id,
      user_id,
      role_id,
      created_at
    ) VALUES (?, ?, ?, ?)
  `).bind(
    makeId("url"),
    userId,
    role.id,
    now
  ).run();
}

async function inferRoles(env, email, phone, userId, now){
  const existing = await env.DB.prepare(`
    SELECT r.name
    FROM auth_user_roles ur
    JOIN auth_roles r ON r.id = ur.role_id
    WHERE ur.user_id = ?
    LIMIT 1
  `).bind(userId).first();

  if(existing) return;

  await ensureRole(env, userId, "talent", now);
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
  const otpCode = norm(body?.otp_code);
  const challengeId = norm(body?.challenge_id);

  if(!otpCode){
    return jsonInvalid("otp_code_required");
  }

  const hasEmail = !!email;
  const hasPhone = !!phone;

  if(!hasEmail && !hasPhone && !challengeId){
    return jsonInvalid("identity_or_challenge_required");
  }

  if(hasEmail && !isEmail(email)){
    return jsonInvalid("invalid_email");
  }

  const now = Math.floor(Date.now() / 1000);
  const ipAddress = getClientIp(request);
  const userAgent = getUserAgent(request);

  try{
    let challenge;

    if(challengeId){
      challenge = await env.DB.prepare(`
        SELECT id, identity_type, identity_value, code, code_hash, status, expires_at
        FROM auth_otp_challenges
        WHERE id = ?
        LIMIT 1
      `).bind(challengeId).first();
    } else if(hasEmail){
      challenge = await env.DB.prepare(`
        SELECT id, identity_type, identity_value, code, code_hash, status, expires_at
        FROM auth_otp_challenges
        WHERE identity_type = 'email'
          AND identity_value = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).bind(email).first();
    } else {
      challenge = await env.DB.prepare(`
        SELECT id, identity_type, identity_value, code, code_hash, status, expires_at
        FROM auth_otp_challenges
        WHERE identity_type = 'phone'
          AND identity_value = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).bind(phone).first();
    }

    if(!challenge){
      return jsonForbidden("otp_challenge_not_found");
    }

    if(String(challenge.status || "") !== "pending"){
      return jsonForbidden("otp_not_pending");
    }

    if(Number(challenge.expires_at || 0) < now){
      await env.DB.prepare(`
        UPDATE auth_otp_challenges
        SET status = 'expired', updated_at = ?
        WHERE id = ?
      `).bind(now, challenge.id).run();
      return jsonForbidden("otp_expired");
    }

    const expectedHash = await hashOtp(
      String(challenge.identity_type || ""),
      String(challenge.identity_value || ""),
      otpCode
    );

    const validByHash = String(challenge.code_hash || "") === expectedHash;
    const validByLegacy = String(challenge.code || "") === otpCode;

    if(!validByHash && !validByLegacy){
      await env.DB.prepare(`
        UPDATE auth_otp_challenges
        SET attempt_count = COALESCE(attempt_count, 0) + 1,
            updated_at = ?
        WHERE id = ?
      `).bind(now, challenge.id).run();

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
        ) VALUES (?, NULL, ?, ?, ?, ?, 0, 'invalid_otp', ?)
      `).bind(
        `lge_${crypto.randomUUID()}`,
        String(challenge.identity_type || ""),
        String(challenge.identity_value || ""),
        ipAddress,
        userAgent,
        now
      ).run();

      return jsonForbidden("invalid_otp_code");
    }

    const identityType = String(challenge.identity_type || "");
    const identityValue = String(challenge.identity_value || "");

    let user;
    if(identityType === "email"){
      user = await env.DB.prepare(`
        SELECT id, email, phone, display_name, status
        FROM auth_users
        WHERE email = ?
        LIMIT 1
      `).bind(identityValue).first();
    } else {
      user = await env.DB.prepare(`
        SELECT id, email, phone, display_name, status
        FROM auth_users
        WHERE phone = ?
        LIMIT 1
      `).bind(identityValue).first();
    }

    if(!user){
      const userId = makeId("usr");
      const emailVal = identityType === "email" ? identityValue : "";
      const phoneVal = identityType === "phone" ? identityValue : "";
      const displayName = emailVal ? emailVal.split("@")[0] : phoneVal;

      await env.DB.prepare(`
        INSERT INTO auth_users (
          id,
          email,
          phone,
          display_name,
          status,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, 'active', ?, ?)
      `).bind(
        userId,
        emailVal || null,
        phoneVal || null,
        displayName || "",
        now,
        now
      ).run();

      user = {
        id: userId,
        email: emailVal,
        phone: phoneVal,
        display_name: displayName,
        status: "active"
      };
    }

    if(String(user.status || "active") !== "active"){
      return jsonForbidden("user_inactive");
    }

    await inferRoles(env, user.email || "", user.phone || "", user.id, now);

    await env.DB.prepare(`
      UPDATE auth_otp_challenges
      SET status = 'verified',
          used_at = ?,
          updated_at = ?
      WHERE id = ?
    `).bind(now, now, challenge.id).run();

    const fingerprint = makeFingerprint(request, user.id);

    const trustedDevice = await env.DB.prepare(`
      SELECT id, status
      FROM auth_trusted_devices
      WHERE user_id = ?
        AND device_fingerprint = ?
      LIMIT 1
    `).bind(user.id, fingerprint).first();

    let deviceVerified = false;

    if(trustedDevice && String(trustedDevice.status || "") === "active"){
      deviceVerified = true;
      await env.DB.prepare(`
        UPDATE auth_trusted_devices
        SET
          last_ip_address = ?,
          last_user_agent = ?,
          last_seen_at = ?,
          updated_at = ?
        WHERE id = ?
      `).bind(
        ipAddress,
        userAgent,
        now,
        now,
        trustedDevice.id
      ).run();
    } else {
      await env.DB.prepare(`
        INSERT OR IGNORE INTO auth_trusted_devices (
          id,
          user_id,
          device_fingerprint,
          device_label,
          last_ip_address,
          last_user_agent,
          status,
          last_seen_at,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
      `).bind(
        `dev_${crypto.randomUUID()}`,
        user.id,
        fingerprint,
        "New Device",
        ipAddress,
        userAgent,
        now,
        now,
        now
      ).run();

      await createRiskFlag(env, {
        user_id: user.id,
        risk_type: "device_anomaly",
        severity: "medium",
        payload: {
          ip_address: ipAddress,
          user_agent: userAgent
        }
      });
    }

    const sessionId = makeId("ses");
    const sessionToken = makeSessionToken();
    const sessionTokenHash = await hashSessionToken(sessionToken);
    const expiresAt = now + (60 * 60 * 24 * 14);

    await env.DB.prepare(`
      INSERT INTO auth_sessions (
        id,
        user_id,
        session_token,
        session_token_hash,
        status,
        device_info,
        ip_address,
        expires_at,
        created_at,
        updated_at,
        last_seen_at
      ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
    `).bind(
      sessionId,
      user.id,
      sessionToken,
      sessionTokenHash,
      userAgent,
      ipAddress,
      expiresAt,
      now,
      now,
      now
    ).run();

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
      ) VALUES (?, ?, ?, ?, ?, ?, 1, 'otp_verified', ?)
    `).bind(
      `lge_${crypto.randomUUID()}`,
      user.id,
      identityType,
      identityValue,
      ipAddress,
      userAgent,
      now
    ).run();

    const rolesRes = await env.DB.prepare(`
      SELECT r.name
      FROM auth_user_roles ur
      JOIN auth_roles r ON r.id = ur.role_id
      WHERE ur.user_id = ?
      ORDER BY r.name ASC
    `).bind(user.id).all();

    const roles = (rolesRes.results || []).map(x => String(x.name || "")).filter(Boolean);
    const portalRoles = roles.filter(r => ["super_admin","admin","security_admin","audit_admin","ops_admin","staff","client","talent"].includes(r));

    let nextPath = "/app/pages/sso/session-check.html";
    if(!deviceVerified){
      nextPath = `/app/pages/sso/device-verification.html?identity=${encodeURIComponent(identityValue)}&challenge_id=${encodeURIComponent(challenge.id)}`;
    } else if(portalRoles.length > 1){
      nextPath = "/app/pages/sso/choose-role.html";
    }

    const res = jsonOk({
      verified: true,
      device_verified: deviceVerified,
      next_path: nextPath,
      user: {
        id: user.id,
        email: user.email || "",
        phone: user.phone || "",
        display_name: user.display_name || ""
      },
      roles,
      session_id: sessionId,
      expires_at: expiresAt
    });

    res.headers.set("set-cookie", buildSessionCookie(sessionToken));
    return res;
  } catch(err){
    return jsonError("verify_otp_failed");
  }
}
