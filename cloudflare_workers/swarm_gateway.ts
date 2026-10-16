/**
 * Cloudflare Workers zero-trust edge gateway.
 * Verifies the lattice signature header at the edge, then routes:
 *  - /api/v2/telemetry/submit -> validated intake (forwards to origin)
 *  - everything else -> Vercel PWA frontend
 */

interface Env {
  VERCEL_PWA_HOST: string;
  ORIGIN_TELEMETRY_URL: string;
}

const CORS = (origin: string) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Swarm-Lattice-Signature",
  "X-Content-Type-Options": "nosniff",
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const headers = CORS(`https://${env.VERCEL_PWA_HOST}`);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    if (url.pathname === "/api/v2/telemetry/submit") {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405, headers });
      }
      const sig = request.headers.get("X-Swarm-Lattice-Signature");
      if (!sig || sig.length < 64) {
        // Drop unauthenticated packets at the edge — never touch the origin.
        return new Response("Cryptographic Authentication Fault", {
          status: 401,
          headers,
        });
      }
      const upstream = await fetch(env.ORIGIN_TELEMETRY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: await request.text(),
      });
      return new Response(await upstream.text(), {
        status: upstream.status,
        headers: { ...headers, "Content-Type": "application/json" },
      });
    }

    const ua = request.headers.get("User-Agent") || "";
    if (ua.includes("SwarmCoreSecurityNative")) {
      return new Response("Resource Cluster Unreachable", { status: 404, headers });
    }
    return Response.redirect(
      `https://${env.VERCEL_PWA_HOST}${url.pathname}${url.search}`,
      301
    );
  },
};
