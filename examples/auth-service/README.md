# Auth Service Example (issues tokens)

What it demonstrates:

- Implements adapters: CredentialChecker, RoleProvider, RoleVersionProvider
- Uses JwtTokenProvider with configurable algorithm (HS256/RS256/EdDSA)
- Calls doAuthenticate() to return an access token

Run (from repo root):

- npm run build
- node dist-examples/auth-service/index.js
