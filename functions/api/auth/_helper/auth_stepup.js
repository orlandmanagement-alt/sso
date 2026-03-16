import { getNow, makeId, makeOtp } from "./auth_session.js";
import { insertStepUp, findLatestStepUp, updateStepUpStatus } from "./auth_queries.js";

export async function createStepUpChallenge(env, userId, reason){
  const now = getNow();
  const expiresAt = now + 300;
  const id = makeId("sup");
  const code = makeOtp();

  await insertStepUp(env, {
    id,
    user_id: userId,
    reason,
    code,
    expires_at: expiresAt,
    created_at: now
  });

  return {
    challenge_id: id,
    reason,
    expires_at: expiresAt
  };
}

export async function verifyStepUpChallenge(env, userId, reason, otpCode){
  const now = getNow();
  const row = await findLatestStepUp(env, userId, reason);

  if(!row){
    return { ok: false, reason: "step_up_not_requested" };
  }

  if(Number(row.expires_at || 0) < now){
    await updateStepUpStatus(env, row.id, "expired");
    return { ok: false, reason: "step_up_expired" };
  }

  if(String(row.code || "") !== String(otpCode || "")){
    return { ok: false, reason: "invalid_step_up_code" };
  }

  await updateStepUpStatus(env, row.id, "verified");
  return { ok: true, verified: true, reason };
}
