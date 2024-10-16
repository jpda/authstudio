namespace authstudio;

public class StoredEntity
{
    public string Id { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

}

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

    private string _configurationUri = "";
    public string ConfigurationUri { get { return string.IsNullOrEmpty(_configurationUri) ? AutoConfigurationUri : _configurationUri; } set { _configurationUri = value; } }

}

public class ClientAppModel
{
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string RedirectUri { get; set; } = "";
}

public class AuthorizeParameterModel {
    public List<string> Scopes { get; set; } = new List<string> { "openid", "profile" };
    public string ScopeParameter { get { return string.Join(' ', Scopes); } set { Scopes.Clear(); Scopes.AddRange(value.Split(' ')); } }
    public string ResponseType { get; set; } = "code";
}

public class AuthorizeRequestModel
{
    // todo: put cascade here? or too opaque?
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public IssuerModel Issuer { get; set; } = new IssuerModel();
    public ClientAppModel ClientApp { get; set; } = new ClientAppModel();
    public PkceChallengeModel PkceChallenge { get; set; } = new PkceChallengeModel();
    public AuthorizeParameterModel AuthorizeParameters { get; set; } = new AuthorizeParameterModel();

    public string AuthorizeUrl
    {
        get
        {
            var authorizeParameters = new Dictionary<string, string?>
            {
                { "client_id", ClientApp.ClientId },
                { "redirect_uri", ClientApp.RedirectUri },
                { "response_type", AuthorizeParameters.ResponseType },
                { "scope", AuthorizeParameters.ScopeParameter },
                { "code_challenge", PkceChallenge.CodeChallenge },
                { "code_challenge_method", PkceChallenge.CodeChallengeMethod.ToString() },
                { "state", Id }
            };
            return Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(Issuer.AuthorizeEndpoint, authorizeParameters);
        }
        set { }
    }
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