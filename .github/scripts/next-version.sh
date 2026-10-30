#!/usr/bin/env bash
# Print the next release tag.
#
# The first tag is v1.0.0. After that:
#   major  BREAKING CHANGE: footer, BREAKING-CHANGE: footer, or type! (feat!:)
#   minor  a commit subject that starts with feat:
#   patch  anything else
#
# Usage: next-version.sh auto|patch|minor|major
# auto keeps the tag already on HEAD. An explicit bump always moves forward.
set -eu

bump="${1:-auto}"
case "$bump" in
    auto|patch|minor|major) ;;
    *)
        echo "bump must be auto, patch, minor, or major" >&2
        exit 1
        ;;
esac

exact='^v[0-9]+\.[0-9]+\.[0-9]+$'
last="$(git tag -l --sort=-v:refname | grep -E "$exact" | head -n 1 || true)"
head_tag="$(git tag --points-at HEAD --sort=-v:refname | grep -E "$exact" | head -n 1 || true)"

if [ "$bump" = "auto" ] && [ -n "$head_tag" ]; then
    printf '%s\n' "$head_tag"
    exit 0
fi

if [ -z "$last" ]; then
    printf '%s\n' "v1.0.0"
    exit 0
fi

if [ "$bump" = "auto" ]; then
    messages="$(git log "${last}..HEAD" --pretty=%B)"
    if printf '%s\n' "$messages" | grep -Eq 'BREAKING CHANGE:|BREAKING-CHANGE:|^[a-z]+(\([^)]*\))?!:'; then
        bump=major
    elif printf '%s\n' "$messages" | grep -Eq '^feat(\([^)]*\))?:'; then
        bump=minor
    else
        bump=patch
    fi
fi

version="${last#v}"
major="${version%%.*}"
rest="${version#*.}"
minor="${rest%%.*}"
patch="${rest#*.}"

case "$bump" in
    major)
        major=$((major + 1))
        minor=0
        patch=0
        ;;
    minor)
        minor=$((minor + 1))
        patch=0
        ;;
    patch)
        patch=$((patch + 1))
        ;;
esac

printf 'v%s.%s.%s\n' "$major" "$minor" "$patch"
