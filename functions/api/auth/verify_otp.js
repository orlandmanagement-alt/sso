import { readJson } from "../../_lib/validate.js";
import { onVerifyOtp } from "../../services/auth/verify_otp_service.js";

export async function onRequestPost({ request, env }){
  const body = await readJson(request) || {};
  return onVerifyOtp({ request, env, body });
}
