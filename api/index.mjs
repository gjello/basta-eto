import { handler } from "../netlify/functions/api.mjs";

export default async function vercelHandler(request, response) {
  const url = new URL(request.url || "/", "http://localhost");
  const forwardedFor = request.headers["x-forwarded-for"];
  const clientIp = typeof forwardedFor === "string"
    ? forwardedFor.split(",")[0].trim()
    : request.socket?.remoteAddress || "";
  const body = request.body == null
    ? ""
    : typeof request.body === "string"
      ? request.body
      : JSON.stringify(request.body);

  const result = await handler({
    httpMethod: request.method,
    headers: {
      ...request.headers,
      "x-nf-client-connection-ip": clientIp
    },
    body,
    queryStringParameters: Object.fromEntries(url.searchParams.entries())
  });

  response.statusCode = result.statusCode;
  for (const [name, value] of Object.entries(result.headers || {})) {
    response.setHeader(name, value);
  }
  response.end(result.body);
}
