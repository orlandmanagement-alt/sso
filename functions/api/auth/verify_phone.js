import { onVerifyPhone } from "../../services/auth/stepup_service.js";

export async function onRequestPost({ request, env }){
  return onVerifyPhone({ request, env });
}
