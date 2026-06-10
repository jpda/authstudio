namespace authstudio;

public class IssuerModel
{
    public string Issuer { get; set; } = "";
    public string AutoConfigurationUri
    {
        get { return $"{Issuer}/.well-known/openid-configuration"; }
        set { }
    }
    public string AuthorizeEndpoint { get; set; } = "";
    public string TokenEndpoint { get; set; } = "";
    public string UserInfoEndpoint { get; set; } = "";
    public string JwksUri { get; set; } = "";
    public string IntrospectionEndpoint { get; set; } = "";
    public string PushedAuthorizationRequestEndpoint { get; set; } = "";
    public bool RequirePushedAuthorizationRequests { get; set; }

    private string _configurationUri = "";
    public string ConfigurationUri { get { return string.IsNullOrEmpty(_configurationUri) ? AutoConfigurationUri : _configurationUri; } set { _configurationUri = value; } }

    public bool? ClientIdMetadataDocumentSupported { get; set; }

}

public class ClientAppModel
{
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public TokenClientAuthMethod TokenAuthMethod { get; set; } = TokenClientAuthMethod.None;
    public string SigningPrivateKeyJwk { get; set; } = "";
    public string SigningAlgorithm { get; set; } = "ES256";
}

public class AuthorizeParameterModel {
    public List<string> Scopes { get; set; } = new List<string> { "openid", "profile" };
    public string ScopeParameter { get { return string.Join(' ', Scopes); } set { Scopes.Clear(); Scopes.AddRange(value.Split(' ')); } }
    public string ResponseType { get; set; } = "code";
    public string ResponseMode { get; set; } = "";
    public bool UsePushedAuthorization { get; set; }
}

public class AuthorizeRequestModel
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public IssuerModel Issuer { get; set; } = new IssuerModel();
    public ClientAppModel ClientApp { get; set; } = new ClientAppModel();
    public PkceChallengeModel PkceChallenge { get; set; } = new PkceChallengeModel();
    public AuthorizeParameterModel AuthorizeParameters { get; set; } = new AuthorizeParameterModel();
    public string? PushedRequestUri { get; set; }

    public bool CanUsePar =>
        !string.IsNullOrEmpty(Issuer.PushedAuthorizationRequestEndpoint);

    public bool UsesPar =>
        AuthorizeParameters.UsePushedAuthorization && CanUsePar;

    public string AuthorizeUrl => UsesPar && !string.IsNullOrEmpty(PushedRequestUri)
        ? OAuthAuthorizationClient.BuildFrontChannelAuthorizeUrl(this, PushedRequestUri)
        : OAuthAuthorizationClient.BuildDirectAuthorizeUrl(this);

    public string PreviewAuthorizeUrl => UsesPar
        ? OAuthAuthorizationClient.BuildFrontChannelAuthorizeUrl(this, "urn:ietf:params:oauth:request_uri:…")
        : OAuthAuthorizationClient.BuildDirectAuthorizeUrl(this);

    public IReadOnlyList<KeyValuePair<string, string>> GetQueryParameters(string? url = null)
    {
        var authorizeUrl = url ?? AuthorizeUrl;
        if (string.IsNullOrEmpty(authorizeUrl))
        {
            return Array.Empty<KeyValuePair<string, string>>();
        }

        var query = new Uri(authorizeUrl).Query;
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(query)
            .SelectMany(pair => pair.Value.Select(value => new KeyValuePair<string, string>(pair.Key, value ?? "")))
            .ToList();
    }

    public IReadOnlyList<KeyValuePair<string, string>> GetParPushParameters() =>
        OAuthAuthorizationClient.BuildAuthorizeParameters(this)
            .Where(pair => !string.IsNullOrEmpty(pair.Value))
            .Select(pair => new KeyValuePair<string, string>(pair.Key, pair.Value!))
            .ToList();
}

public class RedeemCodeModel
{
    public string Code { get; set; } = "";
    public string CodeVerifier { get; set; } = "";
    public string GrantType { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public ClientAppModel Client { get; set; } = new ClientAppModel();
}