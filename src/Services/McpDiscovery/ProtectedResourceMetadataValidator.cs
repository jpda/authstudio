namespace authstudio;

public static class ProtectedResourceMetadataValidator
{
    public static IReadOnlyList<ComplianceCheck> Validate(
        ProtectedResourceMetadataDocument metadata,
        string canonicalResourceUri)
    {
        var checks = new List<ComplianceCheck>();

        if (string.IsNullOrWhiteSpace(metadata.Resource))
        {
            checks.Add(new ComplianceCheck(
                "prm-resource",
                "resource field",
                DiscoveryStepStatus.Failed,
                "Protected resource metadata must include a resource identifier.",
                "RFC 9728"));
        }
        else if (!ResourceMatches(metadata.Resource, canonicalResourceUri))
        {
            checks.Add(new ComplianceCheck(
                "prm-resource-match",
                "resource matches MCP URL",
                DiscoveryStepStatus.Warning,
                $"Metadata resource '{metadata.Resource}' differs from canonical MCP URI '{canonicalResourceUri}'.",
                "RFC 8707 / MCP"));
        }
        else
        {
            checks.Add(new ComplianceCheck(
                "prm-resource-match",
                "resource matches MCP URL",
                DiscoveryStepStatus.Success,
                "Resource identifier matches the canonical MCP server URI.",
                "RFC 9728"));
        }

        if (metadata.AuthorizationServers.Count == 0)
        {
            checks.Add(new ComplianceCheck(
                "prm-authorization-servers",
                "authorization_servers",
                DiscoveryStepStatus.Failed,
                "Protected resource metadata must list at least one authorization server.",
                "RFC 9728 / MCP"));
        }
        else
        {
            checks.Add(new ComplianceCheck(
                "prm-authorization-servers",
                "authorization_servers",
                DiscoveryStepStatus.Success,
                $"Found {metadata.AuthorizationServers.Count} authorization server(s). Clients typically use the first entry.",
                "RFC 9728"));

            foreach (var server in metadata.AuthorizationServers)
            {
                if (!Uri.TryCreate(server, UriKind.Absolute, out var uri)
                    || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    checks.Add(new ComplianceCheck(
                        "prm-as-https",
                        "authorization server HTTPS",
                        DiscoveryStepStatus.Warning,
                        $"Authorization server '{server}' should use https in production.",
                        "MCP"));
                }
            }
        }

        if (metadata.ScopesSupported.Count == 0)
        {
            checks.Add(new ComplianceCheck(
                "prm-scopes",
                "scopes_supported",
                DiscoveryStepStatus.Info,
                "No scopes_supported advertised. Clients may rely on WWW-Authenticate scope or omit scope.",
                "MCP"));
        }

        return checks;
    }

    private static bool ResourceMatches(string metadataResource, string canonicalResourceUri) =>
        string.Equals(
            metadataResource.TrimEnd('/'),
            canonicalResourceUri.TrimEnd('/'),
            StringComparison.OrdinalIgnoreCase);
}
