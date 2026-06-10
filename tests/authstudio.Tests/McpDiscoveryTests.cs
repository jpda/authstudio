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
                "https://example.com/public/.well-known/oauth-protected-resource/mcp",
                "https://example.com/.well-known/oauth-protected-resource"
            ],
            urls);
    }

    [Fact]
    public void BuildProtectedResourceMetadataUrls_includes_path_insertion_for_nested_mcp_paths()
    {
        var urls = McpResourceUriBuilder.BuildProtectedResourceMetadataUrls(
            "https://mcp.example.com/acme/team1/weather/mcp");

        Assert.Contains(
            "https://mcp.example.com/acme/team1/.well-known/oauth-protected-resource/weather/mcp",
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

    [Fact]
    public void FindBearerChallenge_reads_resource_metadata_when_error_description_contains_commas()
    {
        const string header =
            "Bearer error=\"invalid_token\", error_description=\"Authentication failed. The provided bearer token is invalid, expired, or no longer recognized by the server. To resolve: clear authentication tokens in your MCP client and reconnect. Your client should automatically re-register and obtain new tokens.\", resource_metadata=\"https://mcp.example.com/acme/team1/.well-known/oauth-protected-resource/weather/mcp\"";

        var challenge = WwwAuthenticateParser.FindBearerChallenge(header);

        Assert.NotNull(challenge);
        Assert.Equal(
            "https://mcp.example.com/acme/team1/.well-known/oauth-protected-resource/weather/mcp",
            challenge!.ResourceMetadataUrl);
        Assert.Equal("invalid_token", challenge.Error);
        Assert.Contains("invalid, expired", challenge.ErrorDescription, StringComparison.Ordinal);
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

public class McpDiscoveryLinkTests
{
    [Fact]
    public void BuildPath_percent_encodes_mcp_server_url()
    {
        Assert.Equal(
            "/mcp/https%3A%2F%2Fmcp.example.com%2Facme%2Fteam1%2Fweather%2Fmcp",
            McpDiscoveryLink.BuildPath("https://mcp.example.com/acme/team1/weather/mcp"));
    }

    [Fact]
    public void TryParseRouteSegment_accepts_encoded_and_unencoded_paths()
    {
        Assert.True(McpDiscoveryLink.TryParseRouteSegment(
            "https%3A%2F%2Fmcp.example.com%2Fmcp",
            out var encoded));
        Assert.Equal("https://mcp.example.com/mcp", encoded);

        Assert.True(McpDiscoveryLink.TryParseRouteSegment(
            "https://mcp.example.com/mcp",
            out var plain));
        Assert.Equal("https://mcp.example.com/mcp", plain);
    }

    [Fact]
    public void TryParseUri_reads_query_string_url()
    {
        var uri = new Uri("https://authstudio.example/mcp?url=https%3A%2F%2Fmcp.example.com%2Fmcp");

        Assert.True(McpDiscoveryLink.TryParseUri(uri, out var mcpServerUrl));
        Assert.Equal("https://mcp.example.com/mcp", mcpServerUrl);
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
