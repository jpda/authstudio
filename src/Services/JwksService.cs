using System.Text.Json;

namespace authstudio;

public class JwksService(HttpClient http)
{
    private readonly Dictionary<string, JsonElement> _cache = new(StringComparer.Ordinal);

    public async Task<string?> FindVerificationKeyJsonAsync(string jwksUri, string? kid, string alg)
    {
        var jwks = await GetJwksAsync(jwksUri);
        if (!jwks.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var candidates = keys.EnumerateArray()
            .Where(key => KeySupportsAlgorithm(key, alg))
            .ToList();

        if (candidates.Count == 0)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(kid))
        {
            var matched = candidates.FirstOrDefault(key =>
                key.TryGetProperty("kid", out var kidElement)
                && kidElement.GetString() == kid);

            if (matched.ValueKind != JsonValueKind.Undefined)
            {
                return matched.GetRawText();
            }

            return null;
        }

        return candidates.Count == 1 ? candidates[0].GetRawText() : null;
    }

    private async Task<JsonElement> GetJwksAsync(string jwksUri)
    {
        if (_cache.TryGetValue(jwksUri, out var cached))
        {
            return cached;
        }

        var json = await http.GetStringAsync(jwksUri);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement.Clone();
        _cache[jwksUri] = root;
        return root;
    }

    private static bool KeySupportsAlgorithm(JsonElement key, string alg)
    {
        if (key.TryGetProperty("use", out var use) && use.GetString() is { } useValue
            && !useValue.Equals("sig", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (key.TryGetProperty("alg", out var keyAlg) && keyAlg.GetString() is { } keyAlgValue)
        {
            return keyAlgValue.Equals(alg, StringComparison.OrdinalIgnoreCase);
        }

        var kty = key.TryGetProperty("kty", out var ktyElement) ? ktyElement.GetString() : null;
        return alg switch
        {
            "RS256" or "RS384" or "PS256" => kty == "RSA",
            "ES256" => kty == "EC" && ReadCrv(key) == "P-256",
            "ES384" => kty == "EC" && ReadCrv(key) == "P-384",
            "ES512" => kty == "EC" && ReadCrv(key) == "P-521",
            _ => false
        };
    }

    private static string? ReadCrv(JsonElement key) =>
        key.TryGetProperty("crv", out var crv) ? crv.GetString() : null;
}
