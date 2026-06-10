using System.Text.Json;

namespace authstudio;

public record DiscoveredOpenIdConfiguration(
    string Issuer,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string UserInfoEndpoint,
    string JwksUri,
    string IntrospectionEndpoint,
    bool ClientIdMetadataDocumentSupported);

public static class OpenIdDiscovery
{
    public static async Task<DiscoveredOpenIdConfiguration> FetchAsync(
        HttpClient http,
        string issuer,
        string configurationUri,
        CancellationToken cancellationToken = default)
    {
        var requestUri = ResolveConfigurationUri(issuer, configurationUri);
        using var response = await http.GetAsync(requestUri, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;

        return new DiscoveredOpenIdConfiguration(
            ReadString(root, "issuer"),
            ReadString(root, "authorization_endpoint"),
            ReadString(root, "token_endpoint"),
            ReadString(root, "userinfo_endpoint"),
            ReadString(root, "jwks_uri"),
            ReadString(root, "introspection_endpoint"),
            CimdDefaults.TryReadMetadataDocumentSupport(root));
    }

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

        return $"{issuer.TrimEnd('/')}/.well-known/openid-configuration";
    }

    private static string ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) ? value.GetString() ?? "" : "";
}
