import { readJson } from "../../_lib/validate.js";
import { onRequestOtp } from "../../services/auth/request_otp_service.js";

export async function onRequestPost({ request, env }){
  const body = await readJson(request) || {};
  return onRequestOtp({ request, env, body });
}
