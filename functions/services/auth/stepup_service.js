import { jsonOk } from "../../_lib/response.js";

export async function onStepUpRequest(){
  return jsonOk({
    step_up_required: false,
    message: "step_up_not_enabled"
  });
}

export async function onStepUpVerify(){
  return jsonOk({
    verified: true,
    message: "step_up_not_enabled"
  });
}

export async function onVerifyPhone(){
  return jsonOk({
    verified: true,
    message: "phone_verification_not_enabled"
  });
}

export async function onExchange(){
  return jsonOk({
    exchanged: false,
    message: "exchange_not_enabled"
  });
}

export async function onSyncOtpSettings(){
  return jsonOk({
    synced: true
  });
}
