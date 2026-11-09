# oauth.studio

This app runs at [https://oauth.studio](https://oauth.studio). It's a small, basic app intended to make working with oauth2 & oidc a little easier. Originally written in blazor wasm (by hand!) to make PKCE code flows easier to generate, it has grown into a more comprehensive set of tools for testing different protocol flows and scenarios.

## docker

This is wasm, so it runs in the browser. A container is available if you want to run it locally.

```bash
docker run -p 8080:8080 ghcr.io/jpda/authstudio:latest
```

To set your host for CIMD, set the `AUTHSTUDIO_PUBLIC_ORIGIN` var to your desired public origin, for example:

```bash
docker run -p 8080:8080 -e AUTHSTUDIO_PUBLIC_ORIGIN=http://localhost:8080 ghcr.io/jpda/authstudio:latest
```

## CIMD

This is compliant with the CIMD (draft-01) specification; we use this for testing different CIMD flows. There is a library of pre-configured CIMD scenarios included as well as a CIMD linter at ./cimd/lint. 

Of course, being a wasm app, this is a public client - it has no capabilities to keep secrets securely; the private keypair is included purely for testing the cimd-private flows.

### resolvable negative-test documents

`/cimd-e2e/` holds documents an authorization server can actually fetch and resolve: each `client_id` matches the URL it is served from, unlike the linter samples in `/cimd-samples/`, which use `example.com` and are meant to be pasted into the linter. Each one is valid apart from a single problem the authorization server is expected to refuse.

| Document | Problem | Expected behavior |
|---|---|---|
| `/cimd-e2e/loopback-jwks.json` | `jwks_uri` is `https://127.0.0.1:47123/jwks.json` | refuse to fetch the loopback `jwks_uri` |
| `/cimd-e2e/link-local-jwks.json` | `jwks_uri` is on the link-local metadata address `169.254.169.254` | refuse to fetch the link-local `jwks_uri` |
| `/cimd-e2e/oversized.json` | about 6 KB, over the 5 KB the spec recommends as a size limit | reject the document |
| `/cimd-e2e/redirect-loopback.json` | responds `302` to `https://127.0.0.1:47123/client.json` | do not follow the redirect |

The loopback targets all use port `47123`, so a test can listen on `127.0.0.1:47123` and assert that nothing connected. When self-hosting, `AUTHSTUDIO_PUBLIC_ORIGIN` rewrites these documents too, but the loopback and link-local targets stay fixed.

## privacy

With the exception of two methods for handling response_mode=form_post (which is opt-in) and bypassing CORS restrictions, there is no server-side app processing. These are in ./functions/api for your inspection; these run using cloudflare workers.