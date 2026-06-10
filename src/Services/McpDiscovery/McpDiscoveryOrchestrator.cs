namespace authstudio;

public class McpDiscoveryOrchestrator(DiscoveryFetchService fetchService)
{
    public async Task<McpDiscoverySession> DiscoverAsync(
        string mcpServerUrl,
        int selectedAuthorizationServerIndex = 0,
        CancellationToken cancellationToken = default)
    {
        var session = new McpDiscoverySession
        {
            McpServerUrl = mcpServerUrl.Trim(),
            SelectedAuthorizationServerIndex = selectedAuthorizationServerIndex
        };

        try
        {
            session.CanonicalResourceUri = McpResourceUriBuilder.BuildCanonicalResourceUri(session.McpServerUrl);
        }
        catch (Exception ex)
        {
            session.Steps.Add(FailedStep(
                "canonical-resource",
                "Canonical resource URI",
                session.McpServerUrl,
                ex.Message));
            session.CompletedAt = DateTimeOffset.UtcNow;
            return session;
        }

        var probeStep = await ProbeResourceAsync(session, cancellationToken);
        session.Steps.Add(probeStep);

        var bearer = WwwAuthenticateParser.FindBearerChallenge(session.WwwAuthenticateRaw);
        if (bearer?.ResourceMetadataUrl is { Length: > 0 } headerUrl)
        {
            session.ResourceMetadataUrlFromHeader = headerUrl;
            session.Steps.Add(InfoStep(
                "www-authenticate",
                "WWW-Authenticate",
                $"Found Bearer challenge with resource_metadata and{(string.IsNullOrEmpty(bearer.Scope) ? "out" : "")} scope.",
                bearer.RawValue));
            session.ChallengedScope = bearer.Scope;
        }
        else if (!string.IsNullOrWhiteSpace(session.WwwAuthenticateRaw))
        {
            session.Steps.Add(WarningStep(
                "www-authenticate",
                "WWW-Authenticate",
                "Authorization challenge present but no resource_metadata parameter. Clients will fall back to well-known probing.",
                session.WwwAuthenticateRaw));
        }
        else if (probeStep.ResponseStatusCode == 401)
        {
            session.Steps.Add(WarningStep(
                "www-authenticate",
                "WWW-Authenticate",
                "401 response did not include WWW-Authenticate. Clients will fall back to well-known probing.",
                null));
        }

        var prmStep = await FetchProtectedResourceMetadataAsync(session, cancellationToken);
        session.Steps.Add(prmStep);

        if (session.ProtectedResourceMetadata is null)
        {
            session.CompletedAt = DateTimeOffset.UtcNow;
            session.ComplianceChecks = session.Steps.SelectMany(step => step.Checks).ToList();
            return session;
        }

        session.ComplianceChecks.AddRange(
            ProtectedResourceMetadataValidator.Validate(
                session.ProtectedResourceMetadata,
                session.CanonicalResourceUri));

        if (session.ProtectedResourceMetadata.AuthorizationServers.Count == 0)
        {
            session.CompletedAt = DateTimeOffset.UtcNow;
            return session;
        }

        var index = Math.Clamp(
            selectedAuthorizationServerIndex,
            0,
            session.ProtectedResourceMetadata.AuthorizationServers.Count - 1);
        session.SelectedAuthorizationServerIndex = index;
        session.SelectedAuthorizationServer = session.ProtectedResourceMetadata.AuthorizationServers[index];

        var asStep = await FetchAuthorizationServerMetadataAsync(session, cancellationToken);
        session.Steps.Add(asStep);

        if (session.AuthorizationServerMetadata is not null)
        {
            session.ComplianceChecks.AddRange(
                AuthorizationServerMetadataValidator.Validate(session.AuthorizationServerMetadata));
        }

        session.SuggestedScope = session.ChallengedScope
            ?? (session.ProtectedResourceMetadata.ScopesSupported.Count > 0
                ? string.Join(' ', session.ProtectedResourceMetadata.ScopesSupported)
                : null);

        session.CompletedAt = DateTimeOffset.UtcNow;
        return session;
    }

    private async Task<DiscoveryStep> ProbeResourceAsync(
        McpDiscoverySession session,
        CancellationToken cancellationToken)
    {
        var step = NewStep("resource-probe", "Unauthenticated MCP probe", session.McpServerUrl);
        try
        {
            var getFetch = await fetchService.GetAsync(session.McpServerUrl, cancellationToken);
            DiscoveryFetchResult fetch;
            string methodUsed;

            if (!McpResourceProbe.ShouldSendPostProbe(getFetch.StatusCode))
            {
                fetch = getFetch;
                methodUsed = "GET";
            }
            else
            {
                step.Notes.Add(
                    getFetch.StatusCode == 405
                        ? "GET returned HTTP 405 (POST-only MCP endpoint). Retrying with unauthenticated initialize POST."
                        : $"GET returned HTTP {getFetch.StatusCode}. Retrying with unauthenticated initialize POST.");
                fetch = await fetchService.PostMcpInitializeAsync(session.McpServerUrl, cancellationToken);
                methodUsed = "POST";
            }

            step.RequestMethod = methodUsed;
            ApplyFetch(step, fetch);
            session.WwwAuthenticateRaw = fetch.Headers.TryGetValue("WWW-Authenticate", out var value) ? value : null;

            step.Status = fetch.StatusCode switch
            {
                401 => DiscoveryStepStatus.Success,
                403 => DiscoveryStepStatus.Warning,
                >= 200 and < 300 => DiscoveryStepStatus.Warning,
                _ => DiscoveryStepStatus.Info
            };

            step.Description = DescribeProbeResult(fetch.StatusCode, methodUsed, getFetch.StatusCode);

            if (fetch.StatusCode != 401)
            {
                step.Checks.Add(new ComplianceCheck(
                    "probe-status",
                    "401 challenge",
                    DiscoveryStepStatus.Warning,
                    "MCP clients expect an unauthenticated MCP request to receive HTTP 401.",
                    "MCP"));
            }
            else
            {
                step.Checks.Add(new ComplianceCheck(
                    "probe-status",
                    "401 challenge",
                    DiscoveryStepStatus.Success,
                    methodUsed == "POST"
                        ? "Unauthenticated initialize POST received HTTP 401."
                        : "Unauthenticated request received HTTP 401.",
                    "MCP"));

                if (methodUsed == "POST" && getFetch.StatusCode == 405)
                {
                    step.Checks.Add(new ComplianceCheck(
                        "probe-post-only",
                        "POST-only MCP endpoint",
                        DiscoveryStepStatus.Info,
                        "GET returned HTTP 405, which is valid when the server does not offer an SSE stream.",
                        "MCP Streamable HTTP"));
                }
            }
        }
        catch (Exception ex)
        {
            step.Status = DiscoveryStepStatus.Failed;
            step.Description = ex.Message;
        }

        return step;
    }

    private static string DescribeProbeResult(int statusCode, string methodUsed, int getStatusCode) =>
        statusCode switch
        {
            401 when methodUsed == "POST" && getStatusCode == 405 =>
                "POST-only MCP endpoint returned HTTP 401 with Bearer challenge (GET correctly returned 405).",
            401 when methodUsed == "POST" =>
                "Server challenged the unauthenticated initialize POST (expected for MCP).",
            401 => "Server challenged the unauthenticated request (expected for MCP).",
            403 => "Server returned 403 Forbidden without a classic 401 challenge.",
            >= 200 and < 300 =>
                "Server accepted the unauthenticated MCP request. MCP clients expect a 401 challenge.",
            _ => $"Server returned HTTP {statusCode} to the unauthenticated {methodUsed} probe."
        };

    private async Task<DiscoveryStep> FetchProtectedResourceMetadataAsync(
        McpDiscoverySession session,
        CancellationToken cancellationToken)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(session.ResourceMetadataUrlFromHeader))
        {
            candidates.Add(session.ResourceMetadataUrlFromHeader);
        }

        candidates.AddRange(McpResourceUriBuilder.BuildProtectedResourceMetadataUrls(session.McpServerUrl));

        var step = NewStep("protected-resource-metadata", "Protected resource metadata", candidates[0]);
        var errors = new List<string>();

        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            step.RequestUrl = candidate;
            try
            {
                var (document, fetch) = await ProtectedResourceMetadataDiscovery.FetchAsync(
                    candidate,
                    fetchService,
                    cancellationToken);
                ApplyFetch(step, fetch);
                session.ProtectedResourceMetadata = document;
                step.Status = DiscoveryStepStatus.Success;
                step.Description = $"Fetched RFC 9728 metadata from {candidate}.";
                step.Checks.AddRange(ProtectedResourceMetadataValidator.Validate(document, session.CanonicalResourceUri));
                return step;
            }
            catch (Exception ex)
            {
                errors.Add($"{candidate}: {ex.Message}");
            }
        }

        step.Status = DiscoveryStepStatus.Failed;
        step.Description = "Could not fetch protected resource metadata from the header URL or well-known fallbacks.";
        step.Notes = errors;
        return step;
    }

    private async Task<DiscoveryStep> FetchAuthorizationServerMetadataAsync(
        McpDiscoverySession session,
        CancellationToken cancellationToken)
    {
        var issuer = session.SelectedAuthorizationServer ?? "";
        var step = NewStep("authorization-server-metadata", "Authorization server metadata", issuer);

        try
        {
            var discovery = await AuthorizationServerMetadataDiscovery.DiscoverAsync(
                issuer,
                fetchService,
                cancellationToken);

            session.AuthorizationServerMetadata = discovery.Configuration;
            session.AuthorizationServerMetadataUrl = discovery.MetadataUrl;
            session.AuthorizationServerMetadataKind = discovery.MetadataKind;
            step.RequestUrl = discovery.MetadataUrl;
            step.Status = DiscoveryStepStatus.Success;
            step.Description =
                $"Discovered {(discovery.MetadataKind == AuthorizationServerMetadataKind.OAuthAuthorizationServer ? "OAuth AS" : "OpenID Connect")} metadata.";
            step.Notes = discovery.AttemptedUrls
                .Select(url => url == discovery.MetadataUrl ? $"{url} (selected)" : url)
                .ToList();
            step.Checks.AddRange(AuthorizationServerMetadataValidator.Validate(discovery.Configuration));
        }
        catch (Exception ex)
        {
            step.Status = DiscoveryStepStatus.Failed;
            step.Description = ex.Message;
        }

        return step;
    }

    private static DiscoveryStep NewStep(string id, string title, string? requestUrl) => new()
    {
        Id = id,
        Title = title,
        RequestUrl = requestUrl,
        RequestMethod = "GET"
    };

    private static void ApplyFetch(DiscoveryStep step, DiscoveryFetchResult fetch)
    {
        step.ResponseStatusCode = fetch.StatusCode;
        step.ResponseBody = Truncate(fetch.Body);
        step.FetchVia = fetch.Via;
        step.ResponseHeaders = fetch.Headers.Count == 0
            ? null
            : string.Join("\n", fetch.Headers.Select(pair => $"{pair.Key}: {pair.Value}"));
    }

    private static DiscoveryStep FailedStep(string id, string title, string? url, string message) => new()
    {
        Id = id,
        Title = title,
        RequestUrl = url,
        Status = DiscoveryStepStatus.Failed,
        Description = message
    };

    private static DiscoveryStep InfoStep(string id, string title, string description, string? detail) => new()
    {
        Id = id,
        Title = title,
        Status = DiscoveryStepStatus.Info,
        Description = description,
        ResponseBody = detail
    };

    private static DiscoveryStep WarningStep(string id, string title, string description, string? detail) => new()
    {
        Id = id,
        Title = title,
        Status = DiscoveryStepStatus.Warning,
        Description = description,
        ResponseBody = detail
    };

    private static string Truncate(string value, int maxLength = 8000) =>
        value.Length <= maxLength ? value : value[..maxLength] + "…";
}
