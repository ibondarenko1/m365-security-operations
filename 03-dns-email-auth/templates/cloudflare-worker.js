// cloudflare-worker.js
// Cloudflare Worker that serves the MTA-STS policy file over HTTPS at
// https://mta-sts.<your-domain>/.well-known/mta-sts.txt
// Deployment:
//   1. Create the worker in Cloudflare dashboard (Workers & Pages > Create > Hello World > rename to mta-sts).
//   2. Paste this code into the editor and Deploy.
//   3. Add a route: mta-sts.<your-domain>/* -> this worker
//   4. Add DNS: A record at mta-sts.<your-domain> pointing to 192.0.2.1 (placeholder), Proxied via Cloudflare.
//   5. Add TXT at _mta-sts.<your-domain>: v=STSv1; id=<unique-string-bump-on-change>

const POLICY = `version: STSv1
mode: enforce
mx: *.mail.protection.outlook.com
max_age: 86400
`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/.well-known/mta-sts.txt") {
      return new Response(POLICY, {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "public, max-age=3600",
        },
      });
    }
    return new Response("Not Found", { status: 404 });
  },
};
