import { onSyncOtpSettings } from "../../services/auth/stepup_service.js";

export async function onRequestPost({ request, env }){
  return onSyncOtpSettings({ request, env });
}
