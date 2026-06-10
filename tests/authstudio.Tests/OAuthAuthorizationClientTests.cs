using System.Net;

namespace authstudio.Tests;

public class OAuthAuthorizationClientTests
{
    [Fact]
    public void BuildAuthorizeParameters_includes_form_post_response_mode()
    {
        var request = SampleRequest();
        request.AuthorizeParameters.ResponseMode = "form_post";

        var parameters = OAuthAuthorizationClient.BuildAuthorizeParameters(request);

        Assert.Equal("form_post", parameters["response_mode"]);
    }

    [Fact]
    public void BuildAuthorizeParameters_omits_default_query_response_mode()
    {
        var request = SampleRequest();
        request.AuthorizeParameters.ResponseMode = "query";

        var parameters = OAuthAuthorizationClient.BuildAuthorizeParameters(request);

        Assert.False(parameters.ContainsKey("response_mode"));
    }

    [Fact]
    public void BuildFrontChannelAuthorizeUrl_contains_request_uri()
    {
        var request = SampleRequest();
        var url = OAuthAuthorizationClient.BuildFrontChannelAuthorizeUrl(
            request,
            "urn:ietf:params:oauth:request_uri:abc");

        Assert.Contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc", url);
        Assert.Contains("client_id=https%3A%2F%2Fclient.example%2Fmetadata.json", url);
        Assert.DoesNotContain("code_challenge=", url);
    }

    [Fact]
    public void ParseParResponse_reads_request_uri()
    {
        const string body = """{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}""";

        var result = OAuthAuthorizationClient.ParseParResponse(
            new HttpResponseMessage(HttpStatusCode.Created) { Content = new StringContent(body) },
            body);

        Assert.True(result.IsSuccess);
        Assert.Equal("urn:ietf:params:oauth:request_uri:abc", result.RequestUri);
        Assert.Equal(60, result.ExpiresIn);
    }

    private static AuthorizeRequestModel SampleRequest() => new()
    {
        Id = "state123",
        Issuer = new IssuerModel { AuthorizeEndpoint = "https://as.example/authorize" },
        ClientApp = new ClientAppModel
        {
            ClientId = "https://client.example/metadata.json",
            RedirectUri = "https://client.example/code"
        },
        PkceChallenge = new PkceChallengeModel
        {
            CodeVerifier = "verifier",
            CodeChallenge = "challenge",
            CodeChallengeMethod = ChallengeMethod.S256
        },
        AuthorizeParameters = new AuthorizeParameterModel
        {
            ResponseType = "code",
            ScopeParameter = "openid"
        }
    };
}
