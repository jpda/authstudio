using System.Text.Json;

namespace authstudio;

public static class ProtectedResourceMetadataDiscovery
{
    public static ProtectedResourceMetadataDocument Parse(string json, string sourceUrl)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        return new ProtectedResourceMetadataDocument
        {
            Resource = ReadString(root, "resource"),
            AuthorizationServers = ReadStringArray(root, "authorization_servers"),
            ScopesSupported = ReadStringArray(root, "scopes_supported"),
            RawJson = json,
            SourceUrl = sourceUrl
        };
    }

    public static async Task<(ProtectedResourceMetadataDocument Document, DiscoveryFetchResult Fetch)> FetchAsync(
        string url,
        DiscoveryFetchService fetchService,
        CancellationToken cancellationToken = default)
    {
        var fetch = await fetchService.GetAsync(url, cancellationToken);
        if (!fetch.IsSuccess)
        {
            throw new InvalidOperationException(fetch.Error ?? "Protected resource metadata request failed.");
        }

        if (fetch.StatusCode >= 400)
        {
            throw new InvalidOperationException(
                $"Protected resource metadata returned HTTP {fetch.StatusCode}.");
        }

        if (string.IsNullOrWhiteSpace(fetch.Body))
        {
            throw new InvalidOperationException("Protected resource metadata response was empty.");
        }

        return (Parse(fetch.Body, url), fetch);
    }

    private static string ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) ? value.GetString() ?? "" : "";

    private static List<string> ReadStringArray(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return value.EnumerateArray()
            .Select(item => item.GetString() ?? "")
            .Where(item => !string.IsNullOrEmpty(item))
            .ToList();
    }
}
