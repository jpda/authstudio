namespace authstudio;

public static class AuthorizationServerMetadataValidator
{
    public static IReadOnlyList<ComplianceCheck> Validate(DiscoveredOpenIdConfiguration metadata)
    {
        var checks = new List<ComplianceCheck>();

        if (string.IsNullOrWhiteSpace(metadata.Issuer))
        {
            checks.Add(new ComplianceCheck(
                "as-issuer",
                "issuer",
                DiscoveryStepStatus.Failed,
                "Authorization server metadata must include issuer.",
                "RFC 8414"));
        }

        if (string.IsNullOrWhiteSpace(metadata.AuthorizationEndpoint))
        {
            checks.Add(new ComplianceCheck(
                "as-authorize",
                "authorization_endpoint",
                DiscoveryStepStatus.Failed,
                "authorization_endpoint is required for the authorization code flow.",
                "OAuth 2.1 / MCP"));
        }

        if (string.IsNullOrWhiteSpace(metadata.TokenEndpoint))
        {
            checks.Add(new ComplianceCheck(
                "as-token",
                "token_endpoint",
                DiscoveryStepStatus.Failed,
                "token_endpoint is required to redeem authorization codes.",
                "OAuth 2.1 / MCP"));
        }

        if (metadata.CodeChallengeMethodsSupported.Contains("S256", StringComparer.Ordinal))
        {
            checks.Add(new ComplianceCheck(
                "as-pkce",
                "PKCE S256",
                DiscoveryStepStatus.Success,
                "code_challenge_methods_supported includes S256.",
                "MCP"));
        }
        else
        {
            checks.Add(new ComplianceCheck(
                "as-pkce",
                "PKCE S256",
                DiscoveryStepStatus.Failed,
                "MCP clients must refuse to proceed unless code_challenge_methods_supported includes S256.",
                "MCP"));
        }

        if (metadata.ClientIdMetadataDocumentSupported == true)
        {
            checks.Add(new ComplianceCheck(
                "as-cimd",
                "CIMD",
                DiscoveryStepStatus.Success,
                "client_id_metadata_document_supported is true.",
                "MCP / CIMD"));
        }
        else if (metadata.ClientIdMetadataDocumentSupported == false)
        {
            checks.Add(new ComplianceCheck(
                "as-cimd",
                "CIMD",
                DiscoveryStepStatus.Warning,
                "client_id_metadata_document_supported is false. MCP clients may fall back to DCR or manual registration.",
                "MCP / CIMD"));
        }
        else if (!string.IsNullOrWhiteSpace(metadata.RegistrationEndpoint))
        {
            checks.Add(new ComplianceCheck(
                "as-dcr",
                "Dynamic Client Registration",
                DiscoveryStepStatus.Info,
                "registration_endpoint is advertised for DCR fallback.",
                "RFC 7591"));
        }
        else
        {
            checks.Add(new ComplianceCheck(
                "as-registration",
                "Client registration",
                DiscoveryStepStatus.Warning,
                "Neither CIMD nor registration_endpoint is clearly advertised.",
                "MCP"));
        }

        if (!string.IsNullOrWhiteSpace(metadata.PushedAuthorizationRequestEndpoint))
        {
            checks.Add(new ComplianceCheck(
                "as-par",
                "PAR",
                DiscoveryStepStatus.Info,
                "pushed_authorization_request_endpoint is advertised.",
                "RFC 9126"));
        }

        if (metadata.RequirePushedAuthorizationRequests)
        {
            checks.Add(new ComplianceCheck(
                "as-par-required",
                "PAR required",
                DiscoveryStepStatus.Warning,
                "require_pushed_authorization_requests is true. Clients must use PAR.",
                "RFC 9126"));
        }

        return checks;
    }
}
