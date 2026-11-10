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

### resolvable test documents

`/cimd-e2e/` holds documents an authorization server can actually fetch and resolve: each `client_id` matches the URL it is served from, unlike the linter samples in `/cimd-samples/`, which use `example.com` and are meant to be pasted into the linter. Each one is valid apart from a single property under test.

#### documents that should resolve

These are valid. `private-key-jwt-singular.json` and `private-key-jwt-supported-list.json` describe the same client, in the older singular `token_endpoint_auth_method` format and the newer `token_endpoint_auth_methods_supported` format (CIMD draft-03 section 5). Both use the site's public `/jwks.json`.

| Document | Property under test | Expected behavior |
|---|---|---|
| `/cimd-e2e/private-key-jwt-singular.json` | `token_endpoint_auth_method` is `private_key_jwt`, with `jwks_uri` | resolve; treat as a `private_key_jwt` client |
| `/cimd-e2e/private-key-jwt-supported-list.json` | `token_endpoint_auth_methods_supported` is `["none", "private_key_jwt"]`, with `jwks_uri` | resolve; accept the same client as above |
| `/cimd-e2e/public-supported-list.json` | `token_endpoint_auth_methods_supported` is `["none"]` | resolve; treat as a public client |
| `/cimd-e2e/no-auth-method-with-jwks.json` | neither auth-method property, but `jwks_uri` is `https://127.0.0.1:47123/jwks.json` | resolve; assume `none` (public client) and do not fetch the `jwks_uri` |

#### negative-test documents

Each has one problem the authorization server is expected to refuse.

| Document | Problem | Expected behavior |
|---|---|---|
| `/cimd-e2e/loopback-jwks.json` | `jwks_uri` is `https://127.0.0.1:47123/jwks.json` | refuse to fetch the loopback `jwks_uri` |
| `/cimd-e2e/link-local-jwks.json` | `jwks_uri` is on the link-local metadata address `169.254.169.254` | refuse to fetch the link-local `jwks_uri` |
| `/cimd-e2e/oversized.json` | about 6 KB, over the 5 KB the spec recommends as a size limit | reject the document |
| `/cimd-e2e/redirect-loopback.json` | responds `302` to `https://127.0.0.1:47123/client.json` | do not follow the redirect |
| `/cimd-e2e/private-key-in-jwks.json` | inline `jwks` key includes the private member `d` | reject the document; a published private key proves nothing |
| `/cimd-e2e/symmetric-jwks.json` | inline `jwks` key is symmetric (`kty` `oct`) | reject the document; a shared secret cannot be published |
| `/cimd-e2e/private-key-jwt-without-keys.json` | `private_key_jwt` is supported but there is no `jwks` or `jwks_uri` | reject the document |
| `/cimd-e2e/cross-origin-post-logout.json` | `post_logout_redirect_uris` is on a different origin from the `client_id` | reject the document or that redirect URI |
| `/cimd-e2e/client-credentials-public.json` | public client (`none`) requests the `client_credentials` grant | reject the document |

The loopback targets all use port `47123`, so a test can listen on `127.0.0.1:47123` and assert that nothing connected. When self-hosting, `AUTHSTUDIO_PUBLIC_ORIGIN` rewrites these documents too, but the loopback and link-local targets stay fixed.

## privacy

With the exception of two methods for handling response_mode=form_post (which is opt-in) and bypassing CORS restrictions, there is no server-side app processing. These are in ./functions/api for your inspection; these run using cloudflare workers.