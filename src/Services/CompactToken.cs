using System.Text.Json;

namespace authstudio;

public enum CompactTokenKind
{
    Invalid,
    Jws,
    Jwe
}

public record JweHeaderInfo(
    string Alg,
    string Enc,
    string? Kid,
    string? Typ,
    bool IsDeflated,
    IReadOnlyList<KeyValuePair<string, string>> AdditionalFields);

public record JwsHeaderInfo(
    string Alg,
    string? Kid,
    string? Typ,
    IReadOnlyList<KeyValuePair<string, string>> AdditionalFields);

public enum JwtSignatureStatus
{
    NotChecked,
    Verifying,
    Valid,
    Invalid,
    Unsigned,
    KeysUnavailable,
    KeyNotFound,
    UnsupportedAlgorithm,
    Error
}

public record JwtVerificationResult(
    JwtSignatureStatus Status,
    string Message,
    string? JwksUri = null,
    string? MatchedKid = null);

public static class CompactToken
{
    public static CompactTokenKind GetKind(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return CompactTokenKind.Invalid;
        }

        var parts = token.Split('.');
        return parts.Length switch
        {
            3 => CompactTokenKind.Jws,
            5 => CompactTokenKind.Jwe,
            _ => CompactTokenKind.Invalid
        };
    }

    public static JweHeaderInfo ParseJweHeader(string jwe)
    {
        var parts = jwe.Split('.');
        if (parts.Length != 5)
        {
            throw new FormatException("JWE must contain five segments.");
        }

        using var document = JsonDocument.Parse(JwtEncoding.Base64UrlDecode(parts[0]));
        var root = document.RootElement;

        var known = new HashSet<string>(StringComparer.Ordinal)
        {
            "alg", "enc", "kid", "typ", "zip", "epk", "apu", "apv", "cty"
        };

        var additional = new List<KeyValuePair<string, string>>();
        foreach (var property in root.EnumerateObject().OrderBy(p => p.Name))
        {
            if (!known.Contains(property.Name))
            {
                additional.Add(new KeyValuePair<string, string>(
                    property.Name,
                    FormatJsonElement(property.Value)));
            }
        }

        return new JweHeaderInfo(
            ReadString(root, "alg"),
            ReadString(root, "enc"),
            ReadOptionalString(root, "kid"),
            ReadOptionalString(root, "typ"),
            ReadOptionalString(root, "zip") == "DEF",
            additional);
    }

    public static JwsHeaderInfo ParseJwsHeader(string jws)
    {
        var parts = jws.Split('.');
        if (parts.Length != 3)
        {
            throw new FormatException("Signed JWT must contain three segments.");
        }

        using var document = JsonDocument.Parse(JwtEncoding.Base64UrlDecode(parts[0]));
        return ParseJwsHeader(document.RootElement);
    }

    public static JwsHeaderInfo ParseJwsHeader(JsonElement root)
    {
        var known = new HashSet<string>(StringComparer.Ordinal)
        {
            "alg", "kid", "typ", "cty", "jku", "x5u", "x5c"
        };

        var additional = new List<KeyValuePair<string, string>>();
        foreach (var property in root.EnumerateObject().OrderBy(p => p.Name))
        {
            if (!known.Contains(property.Name))
            {
                additional.Add(new KeyValuePair<string, string>(
                    property.Name,
                    FormatJsonElement(property.Value)));
            }
        }

        return new JwsHeaderInfo(
            ReadString(root, "alg"),
            ReadOptionalString(root, "kid"),
            ReadOptionalString(root, "typ"),
            additional);
    }

    public static string? GetClaimValue(IEnumerable<KeyValuePair<string, string>> claims, string name) =>
        claims.FirstOrDefault(c => c.Key == name).Value;

    public static List<KeyValuePair<string, string>> ParseClaims(string payloadJson)
    {
        using var document = JsonDocument.Parse(payloadJson);
        var claims = new List<KeyValuePair<string, string>>();

        foreach (var property in document.RootElement.EnumerateObject().OrderBy(p => p.Name))
        {
            claims.Add(new KeyValuePair<string, string>(
                property.Name,
                FormatJsonElement(property.Value)));
        }

        return claims;
    }

    public static List<KeyValuePair<string, string>> ParseClaimsFromToken(string token)
    {
        var kind = GetKind(token);
        return kind switch
        {
            CompactTokenKind.Jws => ParseClaims(JwtDecoder.Decode(token).Payload),
            CompactTokenKind.Jwe => throw new InvalidOperationException("JWE payload is encrypted."),
            _ => throw new FormatException("Token is not a JWT or JWE.")
        };
    }

    private static string ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) ? value.GetString() ?? "" : "";

    private static string? ReadOptionalString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) ? value.GetString() : null;

    private static string FormatJsonElement(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? "",
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => value.GetRawText()
    };
}
