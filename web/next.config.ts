import type { NextConfig } from "next";

// The browser always talks to this Next.js server under /api; Next forwards those requests to the FastAPI
// backend. One origin means it also works from a phone on the same Wi-Fi, without CORS setup.
const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  experimental: {
    // Wireshark captures are often tens of MB: the proxy's default 10 MB cap would cut the upload short
    proxyClientMaxBodySize: "500mb",
    // a 100k+ packet capture takes about a minute to analyse; the default proxy wait is 30 s
    proxyTimeout: 300_000,
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_URL}/:path*` }];
  },
};

export default nextConfig;
