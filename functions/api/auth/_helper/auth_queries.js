import { getNow } from "./auth_session.js";

export async function findSessionByToken(env, token){
  return await env.DB.prepare(`
    SELECT
      s.id,
      s.user_id,
      s.session_token,
      s.status,
      s.expires_at,
      s.created_at,
      u.email,
      u.phone,
      u.display_name,
      u.status AS user_status
    FROM auth_sessions s
    JOIN auth_users u ON u.id = s.user_id
    WHERE s.session_token = ?
    LIMIT 1
  `).bind(token).first();
}

export async function findRolesByUserId(env, userId){
  const res = await env.DB.prepare(`
    SELECT r.name
    FROM auth_user_roles ur
    JOIN auth_roles r ON r.id = ur.role_id
    WHERE ur.user_id = ?
    ORDER BY r.name ASC
  `).bind(userId).all();

  return (res.results || []).map(x => String(x.name || "")).filter(Boolean);
}

export async function findPendingOtpByIdentity(env, identityType, identityValue){
  return await env.DB.prepare(`
    SELECT id, identity_type, identity_value, code, status, expires_at, created_at
    FROM auth_otp_challenges
    WHERE identity_type = ?
      AND identity_value = ?
      AND status = 'pending'
      AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(identityType, identityValue, getNow()).first();
}

export async function insertOtpChallenge(env, payload){
  return await env.DB.prepare(`
    INSERT INTO auth_otp_challenges (
      id,
      identity_type,
      identity_value,
      code,
      status,
      expires_at,
      created_at
    ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
  `).bind(
    payload.id,
    payload.identity_type,
    payload.identity_value,
    payload.code,
    payload.expires_at,
    payload.created_at
  ).run();
}

export async function insertLoginEvent(env, payload){
  return await env.DB.prepare(`
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
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    payload.id,
    payload.user_id || null,
    payload.identity_type || null,
    payload.identity_value || null,
    payload.ip_address || null,
    payload.user_agent || null,
    Number(payload.success_flag || 0),
    payload.reason || null,
    payload.created_at
  ).run();
}

export async function countRecentLoginFailures(env, identityType, identityValue, sinceTs){
  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM auth_login_events
    WHERE identity_type = ?
      AND identity_value = ?
      AND success_flag = 0
      AND created_at >= ?
  `).bind(identityType, identityValue, sinceTs).first();

  return Number(row?.total || 0);
}

export async function insertRiskFlag(env, payload){
  return await env.DB.prepare(`
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
    payload.id,
    payload.user_id || null,
    payload.risk_type,
    payload.severity,
    payload.payload_json || "{}",
    payload.created_at
  ).run();
}

export async function revokeSessionById(env, sessionId){
  return await env.DB.prepare(`
    UPDATE auth_sessions
    SET status = 'revoked'
    WHERE id = ?
  `).bind(sessionId).run();
}

export async function revokeSessionsByUserId(env, userId){
  return await env.DB.prepare(`
    UPDATE auth_sessions
    SET status = 'revoked'
    WHERE user_id = ?
  `).bind(userId).run();
}

export async function listSessionsByUserId(env, userId){
  const rows = await env.DB.prepare(`
    SELECT
      id,
      status,
      device_info,
      ip_address,
      created_at,
      expires_at
    FROM auth_sessions
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).bind(userId).all();

  return rows.results || [];
}

export async function findSessionById(env, sessionId){
  return await env.DB.prepare(`
    SELECT id, user_id, status, expires_at
    FROM auth_sessions
    WHERE id = ?
    LIMIT 1
  `).bind(sessionId).first();
}

export async function findLatestStepUp(env, userId, reason){
  return await env.DB.prepare(`
    SELECT id, code, expires_at, status, created_at
    FROM auth_step_up_challenges
    WHERE user_id = ?
      AND reason = ?
      AND status = 'pending'
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(userId, reason).first();
}

export async function insertStepUp(env, payload){
  return await env.DB.prepare(`
    INSERT INTO auth_step_up_challenges (
      id,
      user_id,
      reason,
      code,
      status,
      expires_at,
      created_at
    ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
  `).bind(
    payload.id,
    payload.user_id,
    payload.reason,
    payload.code,
    payload.expires_at,
    payload.created_at
  ).run();
}

export async function updateStepUpStatus(env, id, status){
  return await env.DB.prepare(`
    UPDATE auth_step_up_challenges
    SET status = ?
    WHERE id = ?
  `).bind(status, id).run();
}
