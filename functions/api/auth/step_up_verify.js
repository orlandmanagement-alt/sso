import { onStepUpVerify } from "../../services/auth/stepup_service.js";

export async function onRequestPost({ request, env }){
  return onStepUpVerify({ request, env });
}
