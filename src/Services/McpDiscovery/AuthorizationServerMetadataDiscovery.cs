using System.Text.Json;

namespace authstudio;

public static class AuthorizationServerMetadataDiscovery
{
    public static IReadOnlyList<string> BuildCandidateUrls(string issuer)
    {
        if (!Uri.TryCreate(issuer.TrimEnd('/'), UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Authorization server issuer must be an absolute URL.");
        }

        var origin = $"{uri.Scheme}://{uri.Authority}";
        var path = uri.AbsolutePath.Trim('/');

        if (string.IsNullOrEmpty(path))
        {
            return
            [
                $"{origin}/.well-known/oauth-authorization-server",
                $"{origin}/.well-known/openid-configuration"
            ];
        }

        return
        [
            $"{origin}/.well-known/oauth-authorization-server/{path}",
            $"{origin}/.well-known/openid-configuration/{path}",
            $"{origin}/{path}/.well-known/openid-configuration"
        ];
    }

    public static async Task<AuthorizationServerDiscoveryResult> DiscoverAsync(
        string issuer,
        DiscoveryFetchService fetchService,
        CancellationToken cancellationToken = default)
    {
        var attempted = new List<string>();
        Exception? lastError = null;

        foreach (var candidate in BuildCandidateUrls(issuer))
        {
            attempted.Add(candidate);
            try
            {
                var fetch = await fetchService.GetAsync(candidate, cancellationToken);
                if (!fetch.IsSuccess || fetch.StatusCode >= 400 || string.IsNullOrWhiteSpace(fetch.Body))
                {
                    continue;
                }

                var configuration = ParseMetadata(fetch.Body);
                if (!IssuerMatches(configuration.Issuer, issuer))
                {
                    continue;
                }

                return new AuthorizationServerDiscoveryResult(
                    configuration,
                    candidate,
                    ClassifyMetadataUrl(candidate),
                    attempted);
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        throw lastError ?? new InvalidOperationException(
            $"Could not discover authorization server metadata for issuer '{issuer}'.");
    }

    public static async Task<DiscoveredOpenIdConfiguration> FetchFromUrlAsync(
        HttpClient http,
        string issuer,
        string configurationUri,
        CancellationToken cancellationToken = default)
    {
        var requestUri = ResolveConfigurationUri(issuer, configurationUri);
        using var response = await http.GetAsync(requestUri, cancellationToken);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var configuration = ParseMetadata(body);

        if (!string.IsNullOrWhiteSpace(issuer) && !IssuerMatches(configuration.Issuer, issuer))
        {
            throw new InvalidOperationException(
                $"Issuer mismatch: metadata issuer '{configuration.Issuer}' does not match '{issuer}'.");
        }

        return configuration;
    }

    public static DiscoveredOpenIdConfiguration ParseMetadata(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        return new DiscoveredOpenIdConfiguration(
            ReadString(root, "issuer"),
            ReadString(root, "authorization_endpoint"),
            ReadString(root, "token_endpoint"),
            ReadString(root, "userinfo_endpoint"),
            ReadString(root, "jwks_uri"),
            ReadString(root, "introspection_endpoint"),
            ReadString(root, "pushed_authorization_request_endpoint"),
            ReadBoolean(root, "require_pushed_authorization_requests"),
            CimdDefaults.TryReadMetadataDocumentSupport(root),
            ReadStringArray(root, "code_challenge_methods_supported"),
            ReadString(root, "registration_endpoint"),
            ReadStringArray(root, "scopes_supported"));
    }

    public static bool IssuerMatches(string metadataIssuer, string expectedIssuer) =>
        string.Equals(
            metadataIssuer.TrimEnd('/'),
            expectedIssuer.TrimEnd('/'),
            StringComparison.Ordinal);

    private static AuthorizationServerMetadataKind ClassifyMetadataUrl(string url) =>
        url.Contains("/oauth-authorization-server", StringComparison.OrdinalIgnoreCase)
            ? AuthorizationServerMetadataKind.OAuthAuthorizationServer
            : AuthorizationServerMetadataKind.OpenIdConnect;

    private static string ResolveConfigurationUri(string issuer, string configurationUri)
    {
        if (!string.IsNullOrWhiteSpace(configurationUri))
        {
            return configurationUri;
        }

        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new InvalidOperationException("Enter an issuer or configuration URL first.");
        }

        return BuildCandidateUrls(issuer)[0];
    }

    private static string ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) ? value.GetString() ?? "" : "";

    private static bool ReadBoolean(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.True;

    private static List<string> ReadStringArray(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return value.EnumerateArray()
            .Select(item => item.GetString() ?? "")
            .Where(item => !string.IsNullOrEmpty(item))
            .ToList();
    }
}
