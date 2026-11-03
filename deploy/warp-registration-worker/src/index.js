const allowedMethods = new Set(["POST", "PATCH", "DELETE"]);

function emptyResponse(status) {
  return new Response(null, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

export default {
  async fetch(request, env) {
    if (!env.BOOTSTRAP_TOKEN || !env.UPSTREAM_BASES) {
      return emptyResponse(503);
    }

    const url = new URL(request.url);
    const prefix = `/${env.BOOTSTRAP_TOKEN}/`;
    if (!url.pathname.startsWith(prefix)) {
      return emptyResponse(404);
    }

    const path = url.pathname.slice(prefix.length);
    if (!/^reg(?:\/[A-Za-z0-9-]+)?$/.test(path)) {
      return emptyResponse(404);
    }
    if (!allowedMethods.has(request.method)) {
      return emptyResponse(405);
    }

    const declaredLength = Number(request.headers.get("Content-Length") || 0);
    if (!Number.isFinite(declaredLength) || declaredLength > 8192) {
      return emptyResponse(413);
    }
    const body = request.method === "DELETE" ? null : await request.arrayBuffer();
    if (body && body.byteLength > 8192) {
      return emptyResponse(413);
    }

    const headers = new Headers({
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "okhttp/3.12.1",
    });
    const authorization = request.headers.get("Authorization");
    if (authorization) {
      headers.set("Authorization", authorization);
    }

    let upstream = null;
    for (const base of env.UPSTREAM_BASES.split("|")) {
      let upstreamRoot;
      try {
        upstreamRoot = new URL(base);
      } catch {
        continue;
      }
      if (upstreamRoot.protocol !== "https:") {
        continue;
      }
      try {
        upstream = await fetch(new URL(path, upstreamRoot), {
          method: request.method,
          headers,
          body,
          redirect: "manual",
        });
      } catch {
        continue;
      }
      if (upstream.status < 500) {
        break;
      }
    }
    if (!upstream) {
      return emptyResponse(502);
    }

    const responseHeaders = new Headers({ "Cache-Control": "no-store" });
    const contentType = upstream.headers.get("Content-Type");
    if (contentType) {
      responseHeaders.set("Content-Type", contentType);
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  },
};
