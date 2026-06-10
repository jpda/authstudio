namespace authstudio;

public static class AuthorizeUrlSyntax
{
    public const string Issuer = "url-issuer";
    public const string ClientId = "url-client-id";
    public const string RedirectUri = "url-redirect-uri";
    public const string Pkce = "url-pkce";
    public const string OAuth = "url-oauth";
    public const string Resource = "url-resource";
    public const string Par = "url-par";
    public const string Other = "url-other";

    private static readonly string[] ParameterOrder =
    [
        "client_id",
        "redirect_uri",
        "response_type",
        "response_mode",
        "scope",
        "resource",
        "code_challenge",
        "code_challenge_method",
        "state",
        "request_uri"
    ];

    public static string GetCategory(string parameterName) => parameterName switch
    {
        "client_id" => ClientId,
        "redirect_uri" => RedirectUri,
        "code_challenge" or "code_challenge_method" => Pkce,
        "scope" or "response_type" or "response_mode" or "state" => OAuth,
        "resource" => Resource,
        "request_uri" => Par,
        _ => Other
    };

    public static IReadOnlyList<KeyValuePair<string, string>> OrderParameters(
        IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var lookup = parameters
            .GroupBy(pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.Ordinal);

        var ordered = new List<KeyValuePair<string, string>>();
        foreach (var key in ParameterOrder)
        {
            if (lookup.TryGetValue(key, out var value))
            {
                ordered.Add(new KeyValuePair<string, string>(key, value));
                lookup.Remove(key);
            }
        }

        foreach (var pair in lookup.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            ordered.Add(pair);
        }

        return ordered;
    }

    public static string? GetBaseUrl(string authorizeUrl)
    {
        if (string.IsNullOrEmpty(authorizeUrl))
        {
            return null;
        }

        var queryIndex = authorizeUrl.IndexOf('?', StringComparison.Ordinal);
        return queryIndex >= 0 ? authorizeUrl[..queryIndex] : authorizeUrl;
    }
}
