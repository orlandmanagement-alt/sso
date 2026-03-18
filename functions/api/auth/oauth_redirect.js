import { redirect } from "../../_lib/response.js";
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const provider = url.searchParams.get("provider");
  const baseUrl = url.origin;
  const redirectUri = `${baseUrl}/api/auth/oauth_callback?provider=${provider}`;

  if (provider === "google") {
    return redirect(`https://accounts.google.com/o/oauth2/v2/auth?client_id=${env.GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=email profile`);
  } else if (provider === "facebook") {
    return redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${env.FB_CLIENT_ID}&redirect_uri=${redirectUri}&scope=email,public_profile`);
  }
  return new Response("Invalid provider", { status: 400 });
}
