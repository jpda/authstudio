namespace authstudio;

public enum DiscoveryStepStatus
{
    Pending,
    Success,
    Warning,
    Failed,
    Skipped,
    Info
}

public enum DiscoveryFetchVia
{
    Browser,
    Proxy
}

public enum AuthorizationServerMetadataKind
{
    OAuthAuthorizationServer,
    OpenIdConnect
}

public record DiscoveryFetchResult(
    string RequestUrl,
    int StatusCode,
    IReadOnlyDictionary<string, string> Headers,
    string Body,
    DiscoveryFetchVia Via,
    string? Error = null)
{
    public bool IsSuccess => string.IsNullOrEmpty(Error);
}

public record ComplianceCheck(
    string Id,
    string Title,
    DiscoveryStepStatus Status,
    string Message,
    string? SpecRef = null);

public class DiscoveryStep
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public DiscoveryStepStatus Status { get; set; } = DiscoveryStepStatus.Pending;
    public string? RequestUrl { get; set; }
    public string RequestMethod { get; set; } = "GET";
    public int? ResponseStatusCode { get; set; }
    public string? ResponseHeaders { get; set; }
    public string? ResponseBody { get; set; }
    public DiscoveryFetchVia? FetchVia { get; set; }
    public List<ComplianceCheck> Checks { get; set; } = [];
    public List<string> Notes { get; set; } = [];
}

public class ProtectedResourceMetadataDocument
{
    public string Resource { get; set; } = "";
    public List<string> AuthorizationServers { get; set; } = [];
    public List<string> ScopesSupported { get; set; } = [];
    public string RawJson { get; set; } = "";
    public string SourceUrl { get; set; } = "";
}

public record AuthorizationServerDiscoveryResult(
    DiscoveredOpenIdConfiguration Configuration,
    string MetadataUrl,
    AuthorizationServerMetadataKind MetadataKind,
    IReadOnlyList<string> AttemptedUrls);

public class McpDiscoverySession
{
    public string McpServerUrl { get; set; } = "";
    public string CanonicalResourceUri { get; set; } = "";
    public DateTimeOffset? CompletedAt { get; set; }
    public List<DiscoveryStep> Steps { get; set; } = [];
    public ProtectedResourceMetadataDocument? ProtectedResourceMetadata { get; set; }
    public int SelectedAuthorizationServerIndex { get; set; }
    public string? SelectedAuthorizationServer { get; set; }
    public DiscoveredOpenIdConfiguration? AuthorizationServerMetadata { get; set; }
    public string? AuthorizationServerMetadataUrl { get; set; }
    public AuthorizationServerMetadataKind? AuthorizationServerMetadataKind { get; set; }
    public List<ComplianceCheck> ComplianceChecks { get; set; } = [];
    public string? WwwAuthenticateRaw { get; set; }
    public string? ChallengedScope { get; set; }
    public string? ResourceMetadataUrlFromHeader { get; set; }
    public string? SuggestedScope { get; set; }
}
