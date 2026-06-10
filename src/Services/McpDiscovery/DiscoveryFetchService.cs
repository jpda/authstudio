using System.Net.Http.Json;
using System.Text;
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

    public Task<DiscoveryFetchResult> GetAsync(string url, CancellationToken cancellationToken = default) =>
        SendAsync(HttpMethod.Get, url, body: null, cancellationToken);

    public Task<DiscoveryFetchResult> PostMcpInitializeAsync(string url, CancellationToken cancellationToken = default) =>
        SendAsync(
            HttpMethod.Post,
            url,
            McpResourceProbe.InitializeRequestJson,
            cancellationToken);

    private async Task<DiscoveryFetchResult> SendAsync(
        HttpMethod method,
        string url,
        string? body,
        CancellationToken cancellationToken)
    {
        try
        {
            var client = clientFactory.CreateClient("DiscoveryClient");
            using var request = BuildRequest(method, url, body);
            using var response = await client.SendAsync(request, cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            return new DiscoveryFetchResult(
                url,
                (int)response.StatusCode,
                ReadHeaders(response),
                responseBody,
                DiscoveryFetchVia.Browser);
        }
        catch (Exception ex) when (ShouldFallbackToProxy(ex))
        {
            return await SendViaProxyAsync(method.Method, url, body, cancellationToken);
        }
    }

    private static HttpRequestMessage BuildRequest(HttpMethod method, string url, string? body)
    {
        var request = new HttpRequestMessage(method, url);
        if (method == HttpMethod.Post && body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            request.Headers.TryAddWithoutValidation("Accept", "application/json, text/event-stream");
        }

        return request;
    }

    private async Task<DiscoveryFetchResult> SendViaProxyAsync(
        string method,
        string url,
        string? body,
        CancellationToken cancellationToken)
    {
        var client = clientFactory.CreateClient("DiscoveryClient");
        using var response = await client.PostAsJsonAsync(
            $"{navigationManager.BaseUri}api/discover",
            new ProxyDiscoveryRequest
            {
                Url = url,
                Method = method,
                Body = body
            },
            cancellationToken);
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

    private sealed class ProxyDiscoveryRequest
    {
        public string Url { get; set; } = "";
        public string Method { get; set; } = "GET";
        public string? Body { get; set; }
    }

    private sealed class ProxyDiscoveryResponse
    {
        public int Status { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public string? Body { get; set; }
        public string? FinalUrl { get; set; }
        public string? Error { get; set; }
    }
}
