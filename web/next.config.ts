import type { NextConfig } from "next";

// The browser always talks to this Next.js server under /api; Next forwards those requests to the FastAPI
// backend. One origin means it also works from a phone on the same Wi-Fi, without CORS setup.
const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_URL}/:path*` }];
  },
};

export default nextConfig;
