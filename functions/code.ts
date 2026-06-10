const RELAY_PARAMS = [
  "code",
  "state",
  "error",
  "error_description",
  "error_uri",
  "session_state",
  "iss",
];

/** @param {{ request: Request }} context */
export async function onRequestPost(context) {
  const contentType = context.request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return Response.redirect(new URL("/code", context.request.url), 302);
  }

  const form = await context.request.formData();
  const params = new URLSearchParams();

  for (const key of RELAY_PARAMS) {
    const value = form.get(key);
    if (typeof value === "string" && value.length > 0) {
      params.set(key, value);
    }
  }

  const query = params.toString();
  const location = query ? `/code?${query}` : "/code";
  return Response.redirect(new URL(location, context.request.url), 302);
}
