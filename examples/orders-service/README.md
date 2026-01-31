# Orders Service Example (verifies tokens)

What it demonstrates:

- Verifies token signed by auth-service
- Enforces RBAC using doAuthorize(required roles)
- Role freshness: compares roleVersion (rv) to current version

Run (from repo root):

- npm run build
- node dist-examples/orders-service/index.js "<PASTE_TOKEN_HERE>"
