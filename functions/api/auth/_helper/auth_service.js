import { getNow, makeId, makeOtp, getClientIp, getUserAgent } from "./auth_session.js";
import {
  findSessionByToken,
  findRolesByUserId,
  findPendingOtpByIdentity,
  insertOtpChallenge,
  insertLoginEvent,
  countRecentLoginFailures,
  insertRiskFlag
} from "./auth_queries.js";

function maskPhone(value = ""){
  const s = String(value || "").trim();
  if(s.length < 6) return s;
  return s.slice(0, 4) + "****" + s.slice(-3);
}

function maskEmail(value = ""){
  const s = String(value || "").trim();
  const parts = s.split("@");
  if(parts.length !== 2) return s;
  const name = parts[0];
  const domain = parts[1];
  if(name.length <= 2) return `${name[0] || "*"}***@${domain}`;
  return `${name.slice(0, 2)}***@${domain}`;
}

export async function getSessionRecord(env, request, parseCookies, getSessionCookieName){
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const token = cookies[getSessionCookieName()] || "";
  if(!token) return null;

  const row = await findSessionByToken(env, token);
  if(!row) return null;
  if(String(row.status || "") !== "active") return null;
  if(Number(row.expires_at || 0) < getNow()) return null;

  const roles = await findRolesByUserId(env, row.user_id);

  return {
    session: row,
    user: {
      id: row.user_id,
      email: row.email || "",
      email_masked: row.email ? maskEmail(row.email) : "",
      phone: row.phone || "",
      phone_masked: row.phone ? maskPhone(row.phone) : "",
      display_name: row.display_name || "",
      status: row.user_status || "active"
    },
    roles
  };
}

export async function createOtpRequest(env, request, identityType, identityValue){
  const code = makeOtp();
  const now = getNow();
  const expiresAt = now + 300;
  const challengeId = makeId("otp");
  const ipAddress = getClientIp(request);
  const userAgent = getUserAgent(request);

  const recent = await findPendingOtpByIdentity(env, identityType, identityValue);
  if(recent){
    return {
      ok: false,
      reason: "otp_already_requested",
      challenge_id: recent.id
    };
  }

  const recentFailures = await countRecentLoginFailures(
    env,
    identityType,
    identityValue,
    now - 600
  );

  if(recentFailures >= 8){
    await insertRiskFlag(env, {
      id: `rsk_${crypto.randomUUID()}`,
      user_id: null,
      risk_type: "otp_abuse",
      severity: "high",
      payload_json: JSON.stringify({
        identity_type: identityType,
        identity_value: identityValue,
        ip_address: ipAddress
      }),
      created_at: now
    });
  }

  await insertOtpChallenge(env, {
    id: challengeId,
    identity_type: identityType,
    identity_value: identityValue,
    code,
    expires_at: expiresAt,
    created_at: now
  });

  await insertLoginEvent(env, {
    id: `lge_${crypto.randomUUID()}`,
    user_id: null,
    identity_type: identityType,
    identity_value: identityValue,
    ip_address: ipAddress,
    user_agent: userAgent,
    success_flag: 0,
    reason: "otp_requested",
    created_at: now
  });

  return {
    ok: true,
    challenge_id: challengeId,
    identity_type: identityType,
    expires_at: expiresAt,
    delivery: "simulated"
  };
}
