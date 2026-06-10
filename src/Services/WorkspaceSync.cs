namespace authstudio;

public static class WorkspaceSync
{
    public static AssertionWorkspaceSnapshot FromWorkspace(IssuerModel? issuer, ClientAppModel? client)
    {
        var snapshot = new AssertionWorkspaceSnapshot();

        if (issuer is not null)
        {
            snapshot.Audience = issuer.TokenEndpoint;
            if (string.IsNullOrEmpty(snapshot.Audience))
            {
                snapshot.Audience = issuer.Issuer;
            }
        }

        if (client is not null)
        {
            snapshot.ClientId = client.ClientId;
            snapshot.PrivateKeyJwk = client.SigningPrivateKeyJwk;
            snapshot.Algorithm = client.SigningAlgorithm;
            snapshot.UsesPrivateKeyJwt = client.TokenAuthMethod == TokenClientAuthMethod.PrivateKeyJwt;
        }

        return snapshot;
    }
}

public class AssertionWorkspaceSnapshot
{
    public string Audience { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string PrivateKeyJwk { get; set; } = "";
    public string Algorithm { get; set; } = "ES256";
    public bool UsesPrivateKeyJwt { get; set; }
}
