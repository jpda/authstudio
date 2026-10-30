# oauth.studio

This is a small, basic app intended to make working with oauth2 & oidc a little easier. Originally written in blazor wasm (by hand!) to make PKCE code flows easier to generate, it has grown into a more comprehensive set of tools for testing different protocol flows and scenarios.

## docker

This is wasm, so it runs in the browser. A container is available if you want to run it locally.

```bash
docker run -p 8080:80 ghcr.io/jpda/oauth.studio:latest
```

To set your host for CIMD, set the `AUTHSTUDIO_PUBLIC_ORIGIN` var to your desired public origin, for example:

```bash
docker run -p 8080:80 -e AUTHSTUDIO_PUBLIC_ORIGIN=http://localhost:8080 ghcr.io/jpda/oauth.studio:latest
```

## CIMD

This is compliant with the CIMD (draft-01) specification; we use this for testing different CIMD flows. There is a library of pre-configured CIMD scenarios included as well as a CIMD linter at ./cimd/lint. 

Of course, being a wasm app, this is a public client - it has no capabilities to keep secrets securely; the private keypair is included purely for testing the cimd-private flows.

## privacy

With the exception of two methods for handling response_mode=form_post (which is opt-in) and bypassing CORS restrictions, there is no server-side app processing. These are in ./functions/api for your inspection; these run using cloudflare workers.