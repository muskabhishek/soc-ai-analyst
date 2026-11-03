# SOC Analyst web app

Next.js 16 + React 19 + Tailwind CSS 4 front end for the FastAPI backend in the parent folder.

```bash
# 1. backend (from the project root)
uvicorn api.main:app --port 8000
# 2. web app (from this folder)
npm install
npm run dev            # http://localhost:3000
```

The browser only talks to this server under `/api/...`; `next.config.ts` forwards those requests to
`API_URL` (default `http://127.0.0.1:8000`). One origin means it also works from a phone on the same Wi-Fi.

- Light / dark / system theme via `next-themes`; colours are CSS variables in `src/app/globals.css`.
- Responsive: sidebar on large screens, bottom tabs on phones, tables become cards on small screens.
- Charts: Recharts. Markdown (method, explanations, report): react-markdown + remark-gfm.
- `package.json` pins `magic-string` to 0.30.x so Tailwind builds on Node 20/21 as well as 22+.
