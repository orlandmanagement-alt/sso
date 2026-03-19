export async function onRequestGet({ request, params }) {
  const provider = params.provider;
  const url = new URL(request.url);
  const host = url.origin; // https://sso.orlandmanagement.com
  let redirectUrl = "";

  if (provider === "facebook") {
    const FB_APP_ID = "929223529699044";
    const cb = encodeURIComponent(`${host}/api/auth/callback/facebook`);
    redirectUrl = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${FB_APP_ID}&redirect_uri=${cb}&scope=email,public_profile`;
  } 
  else if (provider === "tiktok") {
    const TIKTOK_KEY = "awkzny81taard1oq";
    const cb = encodeURIComponent(`${host}/api/auth/callback/tiktok`);
    // Meminta basic info
    redirectUrl = `https://www.tiktok.com/v2/auth/authorize/?client_key=${TIKTOK_KEY}&response_type=code&scope=user.info.basic&redirect_uri=${cb}`;
  } 
  else if (provider === "instagram") {
    // Instagram Basic Display API (Opsional, gunakan ID FB untuk sekarang)
    return new Response("Instagram API Integration Pending", { status: 400 });
  } 
  else {
    return new Response("Provider not supported", { status: 400 });
  }

  return Response.redirect(redirectUrl, 302);
}
