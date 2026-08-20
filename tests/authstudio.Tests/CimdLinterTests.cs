namespace authstudio.Tests;

public class CimdLinterTests
{
    [Fact]
    public void Lint_accepts_public_client_shape()
    {
        const string json = """
            {
              "client_id": "https://oauth.studio/client.json",
              "redirect_uris": ["https://oauth.studio/code"],
              "token_endpoint_auth_method": "none"
            }
            """;

        var checks = CimdLinter.Lint(json, "https://oauth.studio/client.json");

        Assert.DoesNotContain(checks, check => check.Status == DiscoveryStepStatus.Failed);
    }

    [Fact]
    public void Lint_rejects_http_client_id_and_secret_method()
    {
        const string json = """
            {
              "client_id": "http://example.com/client.json",
              "token_endpoint_auth_method": "client_secret_basic"
            }
            """;

        var ids = CimdLinter.Lint(json).Where(check => check.Status == DiscoveryStepStatus.Failed)
            .Select(check => check.Id)
            .ToList();

        Assert.Contains("client-id-https", ids);
        Assert.Contains("auth-method", ids);
    }

    [Fact]
    public void Lint_rejects_dot_segments_in_raw_client_id()
    {
        const string json = """
            { "client_id": "https://example.com/apps/../client.json" }
            """;

        Assert.Contains(CimdLinter.Lint(json), check => check.Id == "client-id-dots");
    }

    [Fact]
    public void Lint_rejects_loopback_jwks_uri()
    {
        const string json = """
            {
              "client_id": "https://example.com/client.json",
              "jwks_uri": "http://127.0.0.1/jwks.json"
            }
            """;

        Assert.Contains(CimdLinter.Lint(json), check => check.Id == "jwks_uri-ssrf");
    }

    [Fact]
    public void Lint_rejects_private_jwk_parameter()
    {
        const string json = """
            {
              "client_id": "https://example.com/client.json",
              "jwks": { "keys": [ { "kty": "EC", "d": "secret" } ] }
            }
            """;

        Assert.Contains(CimdLinter.Lint(json), check => check.Id == "jwks-private");
    }
}

public class CimdSampleCatalogTests
{
    [Fact]
    public void GetHostedPath_uses_local_documents_on_loopback()
    {
        var publicSample = CimdSampleCatalog.All.Single(sample => sample.Id == "public");
        var privateSample = CimdSampleCatalog.All.Single(sample => sample.Id == "private");
        var invalid = CimdSampleCatalog.All.Single(sample => sample.Id == "http-client-id");
        var local = new Uri("https://localhost:5103/");

        Assert.Equal("local.json", CimdSampleCatalog.GetHostedPath(publicSample, local));
        Assert.Equal("private-local.json", CimdSampleCatalog.GetHostedPath(privateSample, local));
        Assert.Equal("cimd-samples/http-client-id.json", CimdSampleCatalog.GetHostedPath(invalid, local));
    }
}

public class CimdDefaultsTests
{
    [Fact]
    public void ShouldDefaultClientId_fills_blank_values()
    {
        Assert.True(CimdDefaults.ShouldDefaultClientId("", null));
        Assert.True(CimdDefaults.ShouldDefaultClientId("   ", false));
    }

    [Fact]
    public void ShouldDefaultClientId_replaces_opaque_ids_when_issuer_supports_cimd()
    {
        Assert.True(CimdDefaults.ShouldDefaultClientId("a1b2c3-registered-client", true));
    }

    [Fact]
    public void ShouldDefaultClientId_keeps_url_client_ids()
    {
        Assert.False(CimdDefaults.ShouldDefaultClientId(
            "https://oauth.studio/cimd-samples/http-client-id.json", true));
        Assert.False(CimdDefaults.ShouldDefaultClientId(
            "https://oauth.studio/private-client.json", true));
    }
}
