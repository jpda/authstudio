namespace authstudio;

public static class McpDiscoveryLink
{
    public const string RoutePrefix = "/mcp";

    public static string BuildPath(string mcpServerUrl) =>
        $"{RoutePrefix}/{Uri.EscapeDataString(mcpServerUrl.Trim())}";

    public static bool TryParseUri(Uri uri, out string mcpServerUrl)
    {
        mcpServerUrl = "";

        if (!string.Equals(uri.AbsolutePath, RoutePrefix, StringComparison.OrdinalIgnoreCase)
            && !uri.AbsolutePath.StartsWith($"{RoutePrefix}/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var routeSegment = uri.AbsolutePath.Length > RoutePrefix.Length + 1
            ? uri.AbsolutePath[(RoutePrefix.Length + 1)..]
            : null;

        if (TryParseRouteSegment(routeSegment, out mcpServerUrl))
        {
            return true;
        }

        var queryUrl = ParseQueryValue(uri.Query, "url");
        if (TryParseAbsoluteUrl(queryUrl, out mcpServerUrl))
        {
            return true;
        }

        return false;
    }

    public static bool TryParseRouteSegment(string? routeSegment, out string mcpServerUrl)
    {
        mcpServerUrl = "";
        if (string.IsNullOrWhiteSpace(routeSegment))
        {
            return false;
        }

        var candidate = Uri.UnescapeDataString(routeSegment.Trim());
        return TryParseAbsoluteUrl(candidate, out mcpServerUrl);
    }

    private static bool TryParseAbsoluteUrl(string? candidate, out string mcpServerUrl)
    {
        mcpServerUrl = "";
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        if (!Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        mcpServerUrl = candidate.Trim();
        return true;
    }

    private static string? ParseQueryValue(string query, string key)
    {
        if (string.IsNullOrEmpty(query))
        {
            return null;
        }

        var parsed = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(query);
        if (!parsed.TryGetValue(key, out var values))
        {
            return null;
        }

        return values.FirstOrDefault();
    }
}
