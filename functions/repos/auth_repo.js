export async function findUserByEmail(env, email_norm){
  return await env.DB.prepare(`
    SELECT id, email_norm, display_name, status
    FROM users
    WHERE email_norm = ?
    LIMIT 1
  `).bind(email_norm).first();
}

export async function getUserRoles(env, user_id){
  const r = await env.DB.prepare(`
    SELECT r.name AS name
    FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.user_id = ?
  `).bind(user_id).all();

  return (r.results || []).map(x => x.name);
}

export async function findInviteByEmailHash(env, email_hash){
  return await env.DB.prepare(`
    SELECT id, role, expires_at, used_at, tenant_id
    FROM invites
    WHERE email_hash = ?
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(email_hash).first();
}
