using System.Text;
using System.Text.Json;
using Microsoft.JSInterop;

namespace authstudio;

public class ClientAssertionService(IJSRuntime jsRuntime, CryptoInteropService cryptoInterop)
{
    public async Task<string> CreateAssertionAsync(
        string clientId,
        string audience,
        string privateKeyJwkJson,
        string? algorithm = null,
        int lifetimeSeconds = 300)
    {
        await cryptoInterop.EnsureReadyAsync();

        using var document = JsonDocument.Parse(privateKeyJwkJson);
        var jwk = document.RootElement;
        var alg = algorithm
            ?? (jwk.TryGetProperty("alg", out var algElement) ? algElement.GetString() : null)
            ?? "ES256";

        var header = new Dictionary<string, object> { ["alg"] = alg, ["typ"] = "JWT" };
        if (jwk.TryGetProperty("kid", out var kidElement) && !string.IsNullOrEmpty(kidElement.GetString()))
        {
            header["kid"] = kidElement.GetString()!;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object>
        {
            ["iss"] = clientId,
            ["sub"] = clientId,
            ["aud"] = audience,
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = now,
            ["exp"] = now + lifetimeSeconds
        };

        var headerSegment = JwtEncoding.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
        var payloadSegment = JwtEncoding.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signingInput = $"{headerSegment}.{payloadSegment}";
        var signature = await jsRuntime.InvokeAsync<string>(
            "authstudioCrypto.signJwt",
            privateKeyJwkJson,
            signingInput,
            alg);

        return $"{signingInput}.{signature}";
    }
}

public static class JwtEncoding
{
    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }
}

public static class JwtDecoder
{
    public static JwtParts Decode(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            throw new FormatException("JWT must contain header and payload segments.");
        }

        return new JwtParts(
            FormatJson(JwtEncoding.Base64UrlDecode(parts[0])),
            FormatJson(JwtEncoding.Base64UrlDecode(parts[1])),
            parts.Length > 2 ? parts[2] : "");
    }

    private static string FormatJson(byte[] json)
    {
        using var document = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
    }
}

public record JwtParts(string Header, string Payload, string Signature);

public static class PrivateKeyJwtGenerator
{
    public const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
}
