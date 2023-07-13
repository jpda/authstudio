namespace authstudio;

public class NotifyOnChangeModel
{
    public event Action? OnChange;
    protected void NotifyChange() => OnChange?.Invoke();
}

public class IssuerModel : NotifyOnChangeModel
{
    public string Issuer { get; set; } = "";
    public string ConfigurationUri { get; set; } = "";
    public string AuthorizeEndpoint { get; set; } = "";
    public string TokenEndpoint { get; set; } = "";
    public string UserInfoEndpoint { get; set; } = "";
    public string JwksUri { get; set; } = "";
    public string IntrospectionEndpoint { get; set; } = "";
}

public class ClientAppModel : NotifyOnChangeModel
{
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string Scope { get; set; } = "";

}

public class AuthorizeRequestModel : NotifyOnChangeModel
{
    // todo: put cascade here? or too opaque?
    public IssuerModel Issuer { get; set; } = new IssuerModel();
    public ClientAppModel ClientApp { get; set; } = new ClientAppModel();
    public PkceChallengeModel PkceChallenge { get; set; } = new PkceChallengeModel();
    public string[] Scopes { get; set; } = new string[] { "openid", "profile" };
    public string ScopeParameter { get { return string.Join(' ', Scopes); } set { } }
    public string ResponseType { get; set; } = "code";
    public string AuthorizeUrl
    {
        get
        {
            var authorizeParameters = new Dictionary<string, string>
            {
                { "client_id", ClientApp.ClientId },
                { "redirect_uri", ClientApp.RedirectUri },
                { "response_type", ResponseType },
                { "scope", ScopeParameter },
                { "code_challenge", PkceChallenge.CodeChallenge },
                { "code_challenge_method", PkceChallenge.CodeChallengeMethod.ToString() },
                // todo: move to storage 
                { "state", PkceChallenge.CodeVerifier }
            };
            return Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(Issuer.AuthorizeEndpoint, authorizeParameters);

            // return
            // $@"{Issuer.AuthorizeEndpoint}?client_id={Client.ClientId}
            // &redirect_uri={Uri.EscapeDataString(Client.RedirectUri)}
            // &response_type={ResponseType}&scope={string.Join(' ', Scopes)} 
            // &code_challenge={PkceModel.CodeChallenge}
            // &code_challenge_method={PkceModel.CodeChallengeMethod}
            // &state={PkceModel.CodeVerifier}".Replace(Environment.NewLine, "").Trim();
            // don't judge me - WebUtilities is deprecated with no replacement and 
            // verbatim strings keep the linebreaks - so stupid
        }
        set { }
    }
}

public class RedeemCodeModel : NotifyOnChangeModel
{
    public string Code { get; set; } = "";
    public string CodeVerifier { get; set; } = "";
    public string GrantType { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public ClientAppModel Client { get; set; } = new ClientAppModel();
}