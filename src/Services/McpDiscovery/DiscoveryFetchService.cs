using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Components;

namespace authstudio;

public class DiscoveryFetchService(
    IHttpClientFactory clientFactory,
    NavigationManager navigationManager)
{
    private static readonly string[] ForwardedHeaders =
    [
        "WWW-Authenticate",
        "Content-Type",
        "Cache-Control"
    ];

    public async Task<DiscoveryFetchResult> GetAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            var client = clientFactory.CreateClient("DiscoveryClient");
            using var response = await client.GetAsync(url, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            return new DiscoveryFetchResult(
                url,
                (int)response.StatusCode,
                ReadHeaders(response),
                body,
                DiscoveryFetchVia.Browser);
        }
        catch (Exception ex) when (ShouldFallbackToProxy(ex))
        {
            return await GetViaProxyAsync(url, cancellationToken);
        }
    }

    private async Task<DiscoveryFetchResult> GetViaProxyAsync(string url, CancellationToken cancellationToken)
    {
        var proxyUrl =
            $"{navigationManager.BaseUri}api/discover?url={Uri.EscapeDataString(url)}";

        var client = clientFactory.CreateClient("DiscoveryClient");
        using var response = await client.GetAsync(proxyUrl, cancellationToken);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<ProxyDiscoveryResponse>(cancellationToken)
            ?? throw new InvalidOperationException("Discovery proxy returned an empty response.");

        if (!string.IsNullOrWhiteSpace(payload.Error))
        {
            return new DiscoveryFetchResult(url, 0, new Dictionary<string, string>(), "", DiscoveryFetchVia.Proxy, payload.Error);
        }

        return new DiscoveryFetchResult(
            payload.FinalUrl ?? url,
            payload.Status,
            payload.Headers ?? new Dictionary<string, string>(),
            payload.Body ?? "",
            DiscoveryFetchVia.Proxy);
    }

    private static IReadOnlyDictionary<string, string> ReadHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in ForwardedHeaders)
        {
            if (response.Headers.TryGetValues(header, out var values))
            {
                headers[header] = string.Join(", ", values);
            }
            else if (response.Content.Headers.TryGetValues(header, out var contentValues))
            {
                headers[header] = string.Join(", ", contentValues);
            }
        }

        return headers;
    }

    private static bool ShouldFallbackToProxy(Exception ex) =>
        ex is HttpRequestException or TaskCanceledException;

    private sealed class ProxyDiscoveryResponse
    {
        public int Status { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public string? Body { get; set; }
        public string? FinalUrl { get; set; }
        public string? Error { get; set; }
    }
}
