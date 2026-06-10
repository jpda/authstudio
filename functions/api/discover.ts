const FORWARDED_HEADERS = ["www-authenticate", "content-type", "cache-control"];

/** @param {{ request: Request }} context */
export async function onRequestGet(context) {
  return handleDiscovery(context.request);
}

/** @param {{ request: Request }} context */
export async function onRequestPost(context) {
  return handleDiscovery(context.request);
}

/** @param {Request} request */
async function handleDiscovery(request) {
  const requestUrl = new URL(request.url);
  let target;
  let method = "GET";
  let body;

  if (request.method === "POST") {
    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ error: "Invalid JSON body." }, 400);
    }

    target = payload?.url;
    method = payload?.method ?? "POST";
    body = payload?.body;
  } else {
    target = requestUrl.searchParams.get("url");
    method = requestUrl.searchParams.get("method") ?? "GET";
    body = requestUrl.searchParams.get("body");
  }

  if (!target) {
    return json({ error: "Missing url." }, 400);
  }

  if (method !== "GET" && method !== "POST") {
    return json({ error: "Only GET and POST are supported." }, 400);
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return json({ error: "Invalid url." }, 400);
  }

  if (parsed.protocol !== "https:") {
    return json({ error: "Only https URLs are allowed." }, 400);
  }

  if (isBlockedHost(parsed.hostname)) {
    return json({ error: "Target host is not allowed." }, 400);
  }

  try {
    /** @type {RequestInit} */
    const init = {
      method,
      redirect: "follow",
      headers: {
        Accept: method === "POST" ? "application/json, text/event-stream" : "*/*",
      },
    };

    if (method === "POST") {
      init.headers["Content-Type"] = "application/json";
      init.body = body ?? "";
    }

    const response = await fetch(parsed.toString(), init);
    const responseBody = await response.text();
    const headers = {};
    for (const name of FORWARDED_HEADERS) {
      const value = response.headers.get(name);
      if (value) {
        headers[name] = value;
      }
    }

    return json({
      status: response.status,
      headers,
      body: responseBody,
      finalUrl: response.url,
    });
  } catch (error) {
    return json({
      error: error instanceof Error ? error.message : "Discovery proxy request failed.",
    }, 502);
  }
}

function json(payload, status = 200) {
  return Response.json(payload, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

function isBlockedHost(hostname) {
  const host = hostname.toLowerCase();

  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }

  if (host === "::1") {
    return true;
  }

  if (/^127\./.test(host)) {
    return true;
  }

  if (/^10\./.test(host)) {
    return true;
  }

  if (/^192\.168\./.test(host)) {
    return true;
  }

  const parts = host.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
    return true;
  }

  if (/^169\.254\./.test(host)) {
    return true;
  }

  return false;
}
