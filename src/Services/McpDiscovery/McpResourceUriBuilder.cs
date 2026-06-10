namespace authstudio;

public static class McpResourceUriBuilder
{
    public static string BuildCanonicalResourceUri(string mcpServerUrl)
    {
        if (!Uri.TryCreate(mcpServerUrl.Trim(), UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Enter a valid absolute MCP server URL.");
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("MCP server URL must use http or https.");
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("Resource URI must not contain a fragment.");
        }

        var builder = new UriBuilder(uri)
        {
            Scheme = uri.Scheme.ToLowerInvariant(),
            Host = uri.Host.ToLowerInvariant(),
            Fragment = ""
        };

        if (string.IsNullOrEmpty(builder.Path) || builder.Path == "/")
        {
            builder.Path = "";
        }
        else
        {
            builder.Path = builder.Path.TrimEnd('/');
        }

        return builder.Uri.ToString();
    }

    public static IReadOnlyList<string> BuildProtectedResourceMetadataUrls(string mcpServerUrl)
    {
        var canonical = BuildCanonicalResourceUri(mcpServerUrl);
        var uri = new Uri(canonical);
        var origin = $"{uri.Scheme}://{uri.Authority}";
        var path = uri.AbsolutePath.Trim('/');

        var candidates = new List<string>();
        if (!string.IsNullOrEmpty(path))
        {
            candidates.Add($"{origin}/.well-known/oauth-protected-resource/{path}");

            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (var index = 1; index < segments.Length; index++)
            {
                var prefix = string.Join('/', segments[..index]);
                var suffix = string.Join('/', segments[index..]);
                candidates.Add($"{origin}/{prefix}/.well-known/oauth-protected-resource/{suffix}");
            }
        }

        candidates.Add($"{origin}/.well-known/oauth-protected-resource");
        return candidates.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
