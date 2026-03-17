export async function createSession(env, row){
  await env.DB.prepare(`
    INSERT INTO sessions (
      id, user_id, token_hash, created_at, expires_at, revoked_at,
      ip_hash, ua_hash, role_snapshot, ip_prefix_hash, last_seen_at,
      roles_json, session_version, revoke_reason
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    row.id,
    row.user_id,
    row.token_hash,
    row.created_at,
    row.expires_at,
    row.revoked_at,
    row.ip_hash,
    row.ua_hash,
    row.role_snapshot,
    row.ip_prefix_hash,
    row.last_seen_at,
    row.roles_json,
    row.session_version,
    row.revoke_reason
  ).run();
}

export async function getSessionById(env, sid){
  return await env.DB.prepare(`
    SELECT *
    FROM sessions
    WHERE id = ?
    LIMIT 1
  `).bind(sid).first();
}

export async function touchSession(env, sid, now){
  await env.DB.prepare(`
    UPDATE sessions
    SET last_seen_at = ?
    WHERE id = ?
  `).bind(now, sid).run();
}

export async function revokeSession(env, sid, now, reason = null){
  await env.DB.prepare(`
    UPDATE sessions
    SET revoked_at = ?, revoke_reason = COALESCE(?, revoke_reason)
    WHERE id = ?
  `).bind(now, reason, sid).run();
}

export async function revokeAllSessions(env, user_id, now, reason = null){
  await env.DB.prepare(`
    UPDATE sessions
    SET revoked_at = ?, revoke_reason = COALESCE(?, revoke_reason)
    WHERE user_id = ? AND revoked_at IS NULL
  `).bind(now, reason, user_id).run();
}

export async function listUserSessions(env, user_id){
  const r = await env.DB.prepare(`
    SELECT id, user_id, created_at, expires_at, revoked_at, last_seen_at, roles_json, session_version, revoke_reason
    FROM sessions
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).bind(user_id).all();

  return r.results || [];
}
