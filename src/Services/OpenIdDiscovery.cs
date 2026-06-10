namespace authstudio;

public record DiscoveredOpenIdConfiguration(
    string Issuer,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string UserInfoEndpoint,
    string JwksUri,
    string IntrospectionEndpoint,
    string PushedAuthorizationRequestEndpoint,
    bool RequirePushedAuthorizationRequests,
    bool? ClientIdMetadataDocumentSupported,
    IReadOnlyList<string> CodeChallengeMethodsSupported,
    string RegistrationEndpoint,
    IReadOnlyList<string> ScopesSupported);

public static class OpenIdDiscovery
{
    public static Task<DiscoveredOpenIdConfiguration> FetchAsync(
        HttpClient http,
        string issuer,
        string configurationUri,
        CancellationToken cancellationToken = default) =>
        AuthorizationServerMetadataDiscovery.FetchFromUrlAsync(http, issuer, configurationUri, cancellationToken);
}
