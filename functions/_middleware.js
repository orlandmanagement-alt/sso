export async function onRequest(context) {
  const request = context.request;
  const origin = request.headers.get("Origin") || "*";
  
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
      }
    });
  }

  const response = await context.next();
  const newResponse = new Response(response.body, response);
  newResponse.headers.set("Access-Control-Allow-Origin", origin);
  newResponse.headers.set("Access-Control-Allow-Credentials", "true");
  return newResponse;
}
