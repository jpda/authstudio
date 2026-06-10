namespace authstudio.Tests;

public class McpResourceUriBuilderTests
{
    [Fact]
    public void BuildCanonicalResourceUri_normalizes_host_and_trims_trailing_slash()
    {
        var uri = McpResourceUriBuilder.BuildCanonicalResourceUri("HTTPS://MCP.example.com/mcp/");

        Assert.Equal("https://mcp.example.com/mcp", uri);
    }

    [Fact]
    public void BuildProtectedResourceMetadataUrls_includes_path_and_root_candidates()
    {
        var urls = McpResourceUriBuilder.BuildProtectedResourceMetadataUrls("https://example.com/public/mcp");

        Assert.Equal(
            [
                "https://example.com/.well-known/oauth-protected-resource/public/mcp",
                "https://example.com/.well-known/oauth-protected-resource"
            ],
            urls);
    }
}

public class WwwAuthenticateParserTests
{
    [Fact]
    public void FindBearerChallenge_reads_resource_metadata_and_scope()
    {
        const string header =
            "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"files:read files:write\", error=\"invalid_token\"";

        var challenge = WwwAuthenticateParser.FindBearerChallenge(header);

        Assert.NotNull(challenge);
        Assert.Equal("https://mcp.example.com/.well-known/oauth-protected-resource", challenge!.ResourceMetadataUrl);
        Assert.Equal("files:read files:write", challenge.Scope);
        Assert.Equal("invalid_token", challenge.Error);
    }
}

public class AuthorizationServerMetadataDiscoveryTests
{
    [Fact]
    public void BuildCandidateUrls_includes_path_insertion_and_append_patterns()
    {
        var urls = AuthorizationServerMetadataDiscovery.BuildCandidateUrls("https://auth.example.com/tenant1");

        Assert.Equal(
            [
                "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
                "https://auth.example.com/.well-known/openid-configuration/tenant1",
                "https://auth.example.com/tenant1/.well-known/openid-configuration"
            ],
            urls);
    }

    [Fact]
    public void IssuerMatches_ignores_trailing_slash()
    {
        Assert.True(AuthorizationServerMetadataDiscovery.IssuerMatches(
            "https://auth.example.com/tenant1/",
            "https://auth.example.com/tenant1"));
    }
}

public class ProtectedResourceMetadataValidatorTests
{
    [Fact]
    public void Validate_fails_when_authorization_servers_missing()
    {
        var checks = ProtectedResourceMetadataValidator.Validate(
            new ProtectedResourceMetadataDocument
            {
                Resource = "https://mcp.example.com/mcp"
            },
            "https://mcp.example.com/mcp");

        Assert.Contains(checks, check => check.Id == "prm-authorization-servers" && check.Status == DiscoveryStepStatus.Failed);
    }
}

public class McpResourceProbeTests
{
    [Theory]
    [InlineData(401, false)]
    [InlineData(405, true)]
    [InlineData(200, true)]
    [InlineData(403, true)]
    public void ShouldSendPostProbe_when_get_is_not_401(int getStatusCode, bool expected)
    {
        Assert.Equal(expected, McpResourceProbe.ShouldSendPostProbe(getStatusCode));
    }
}

public class AuthorizationServerMetadataValidatorTests
{
    [Fact]
    public void Validate_fails_when_pkce_s256_missing()
    {
        var checks = AuthorizationServerMetadataValidator.Validate(new DiscoveredOpenIdConfiguration(
            "https://auth.example.com",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
            "",
            "",
            "",
            "",
            false,
            true,
            ["plain"],
            "",
            []));

        Assert.Contains(checks, check => check.Id == "as-pkce" && check.Status == DiscoveryStepStatus.Failed);
    }
}
