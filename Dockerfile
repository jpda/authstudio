FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*
RUN dotnet workload install wasm-tools
WORKDIR /src
COPY . .
ARG SOURCE_REVISION=dev
ARG REPOSITORY_URL=https://github.com/jpda/authstudio
RUN dotnet publish src/authstudio.csproj -c Release -o /app/publish \
    -p:ContinuousIntegrationBuild=true \
    -p:RepositoryUrl=${REPOSITORY_URL} \
    -p:SourceRevisionId=${SOURCE_REVISION}

FROM nginx:1.27-alpine
LABEL org.opencontainers.image.description "self-hosted oauth.studio"
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/40-cimd-origin.sh /docker-entrypoint.d/40-cimd-origin.sh
COPY --from=build /app/publish/wwwroot /usr/share/nginx/html
# Templates stay pristine so a restarted container can apply a new origin.
RUN find /usr/share/nginx/html -type f \( -name '*.br' -o -name '*.gz' \) -delete \
    && chmod +x /docker-entrypoint.d/40-cimd-origin.sh \
    && mkdir -p /etc/authstudio/cimd \
    && cp /usr/share/nginx/html/client.json \
        /usr/share/nginx/html/private-client.json \
        /usr/share/nginx/html/local.json \
        /usr/share/nginx/html/private-local.json \
        /etc/authstudio/cimd/
EXPOSE 8080
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
