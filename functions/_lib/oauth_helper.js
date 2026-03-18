export async function getGoogleUser(code, env, redirectUri) {
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, code, grant_type: "authorization_code", redirect_uri: redirectUri })
  });
  const token = await tokenRes.json();
  if(!token.access_token) throw new Error("Google Token Failed");
  const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", { headers: { Authorization: `Bearer ${token.access_token}` } });
  return await userRes.json(); // { id, email, name, picture }
}

export async function getFacebookUser(code, env, redirectUri) {
  const tokenRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${env.FB_CLIENT_ID}&redirect_uri=${redirectUri}&client_secret=${env.FB_CLIENT_SECRET}&code=${code}`);
  const token = await tokenRes.json();
  if(!token.access_token) throw new Error("Facebook Token Failed");
  const userRes = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${token.access_token}`);
  return await userRes.json(); // { id, name, email }
}
