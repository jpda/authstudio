#!/bin/sh
# Rewrites the hosted client metadata documents for a self-hosted origin.
# Leave AUTHSTUDIO_PUBLIC_ORIGIN unset to keep the baked-in oauth.studio URLs.
# Example: docker run -e AUTHSTUDIO_PUBLIC_ORIGIN=https://auth.example.com ...
set -eu

origin="${AUTHSTUDIO_PUBLIC_ORIGIN:-}"
template_dir=/etc/authstudio/cimd
html_dir=/usr/share/nginx/html

if [ -z "$origin" ]; then
    exit 0
fi

origin="${origin%/}"

case "$origin" in
    http://*|https://*) ;;
    *)
        echo "AUTHSTUDIO_PUBLIC_ORIGIN must be an origin such as https://host[:port]" >&2
        exit 1
        ;;
esac

host="${origin#*://}"
if ! printf '%s\n' "$host" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._:-]*$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$'; then
    echo "AUTHSTUDIO_PUBLIC_ORIGIN must be an origin with no path, query, or fragment" >&2
    exit 1
fi

for name in client.json private-client.json local.json private-local.json; do
    sed \
        -e "s|https://oauth.studio|${origin}|g" \
        -e "s|https://localhost:5103|${origin}|g" \
        "$template_dir/$name" > "$html_dir/$name"
done

echo "Client metadata documents now use ${origin}"
