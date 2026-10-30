using System.Globalization;
using System.Text;
using System.Text.Json;

namespace authstudio;

public enum JwtSegmentRole
{
    Header,
    Payload,
    Signature,
    EncryptedKey,
    InitializationVector,
    Ciphertext,
    AuthenticationTag,
    Extra
}

public enum JwtTimeTone
{
    Neutral,
    Ok,
    Warning,
    Danger
}

public record JwtSegment(JwtSegmentRole Role, string Label, string Text);

public record JwtDecodedSegment(string? Json, string? Error);

public record JwtHeaderNote(string Text, bool IsWarning);

public record JwtTimeNote(
    string Claim,
    string Label,
    string? AbsoluteUtc,
    string Relative,
    JwtTimeTone Tone,
    bool WasMilliseconds);

public static class JwtPresentation
{
    // Seconds won't reach this until year 2286. Larger numbers are milliseconds.
    private const long MillisecondThreshold = 10_000_000_000L;

    private static readonly (string Claim, string Label)[] TimeClaims =
    [
        ("iat", "Issued at"),
        ("nbf", "Not before"),
        ("auth_time", "Authenticated"),
        ("exp", "Expires")
    ];

    public static string Normalize(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return "";
        }

        var trimmed = token.Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
        {
            trimmed = trimmed[1..^1].Trim();
        }

        if (trimmed.StartsWith("Bearer", StringComparison.OrdinalIgnoreCase)
            && trimmed.Length > 6
            && char.IsWhiteSpace(trimmed[6]))
        {
            trimmed = trimmed[7..].Trim();
        }

        if (!trimmed.Any(char.IsWhiteSpace))
        {
            return trimmed;
        }

        return string.Concat(trimmed.Where(static c => !char.IsWhiteSpace(c)));
    }

    public static IReadOnlyList<JwtSegment> Split(string normalized)
    {
        if (string.IsNullOrEmpty(normalized))
        {
            return [];
        }

        var parts = normalized.Split('.');
        return parts.Length switch
        {
            2 =>
            [
                Segment(JwtSegmentRole.Header, "Header", parts[0]),
                Segment(JwtSegmentRole.Payload, "Payload", parts[1])
            ],
            3 =>
            [
                Segment(JwtSegmentRole.Header, "Header", parts[0]),
                Segment(JwtSegmentRole.Payload, "Payload", parts[1]),
                Segment(JwtSegmentRole.Signature, "Signature", parts[2])
            ],
            5 =>
            [
                Segment(JwtSegmentRole.Header, "Header", parts[0]),
                Segment(JwtSegmentRole.EncryptedKey, "Encrypted key", parts[1]),
                Segment(JwtSegmentRole.InitializationVector, "IV", parts[2]),
                Segment(JwtSegmentRole.Ciphertext, "Ciphertext", parts[3]),
                Segment(JwtSegmentRole.AuthenticationTag, "Auth tag", parts[4])
            ],
            _ => parts.Select((part, index) => Segment(JwtSegmentRole.Extra, $"Segment {index + 1}", part)).ToArray()
        };
    }

    public static string? StructureMessage(int segmentCount) => segmentCount switch
    {
        0 or 3 or 5 => null,
        1 => "A compact JWT is three dot-separated segments, or five when it is encrypted.",
        2 => "Signed JWTs have a third signature segment. This value has a header and payload only.",
        _ => $"A signed JWT has 3 segments and a JWE has 5. This value has {segmentCount}."
    };

    public static string CssClass(JwtSegmentRole role) => role switch
    {
        JwtSegmentRole.Header => "jwt-seg-header",
        JwtSegmentRole.Payload => "jwt-seg-payload",
        JwtSegmentRole.Signature => "jwt-seg-signature",
        JwtSegmentRole.EncryptedKey => "jwt-seg-key",
        JwtSegmentRole.InitializationVector => "jwt-seg-iv",
        JwtSegmentRole.Ciphertext => "jwt-seg-ciphertext",
        JwtSegmentRole.AuthenticationTag => "jwt-seg-tag",
        _ => "jwt-seg-extra"
    };

    public static JwtDecodedSegment DecodeJson(string segment)
    {
        if (string.IsNullOrEmpty(segment))
        {
            return new JwtDecodedSegment(null, "This segment is empty.");
        }

        var badIndex = segment.AsSpan().IndexOfAnyExcept(Base64UrlChars);
        if (badIndex >= 0)
        {
            return new JwtDecodedSegment(null,
                $"Not base64url: '{Printable(segment[badIndex])}' at position {badIndex + 1}. " +
                "Segments use only A–Z, a–z, 0–9, - and _.");
        }

        var unpadded = segment.TrimEnd('=').Length;
        if (unpadded % 4 == 1)
        {
            var count = unpadded == 1 ? "1 character" : $"{unpadded} characters";
            return new JwtDecodedSegment(null,
                $"Not base64url: {count} cannot be a complete encoding. The token may be truncated.");
        }

        byte[] bytes;
        try
        {
            bytes = JwtEncoding.Base64UrlDecode(segment.TrimEnd('='));
        }
        catch (FormatException)
        {
            return new JwtDecodedSegment(null, "Not base64url. The token may be truncated or mangled.");
        }

        try
        {
            using var document = JsonDocument.Parse(bytes);
            return new JwtDecodedSegment(JwtDecoder.PrettyPrint(Encoding.UTF8.GetString(bytes)), null);
        }
        catch (JsonException)
        {
            var preview = Preview(bytes);
            return preview is null
                ? new JwtDecodedSegment(null,
                    $"Decodes from base64url to {bytes.Length} bytes of binary data, not JSON text.")
                : new JwtDecodedSegment(null,
                    $"Decodes from base64url, but the result is not JSON: “{preview}”");
        }
    }

    private static readonly System.Buffers.SearchValues<char> Base64UrlChars =
        System.Buffers.SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=");

    private static string Printable(char c) => char.IsControl(c) ? $"U+{(int)c:X4}" : c.ToString();

    private static string? Preview(byte[] bytes)
    {
        const int Max = 48;
        var text = Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, Max * 4));
        if (text.Length == 0)
        {
            return null;
        }

        var unreadable = text.Count(static c => (char.IsControl(c) && !char.IsWhiteSpace(c)) || c == '\uFFFD');
        if (unreadable * 4 > text.Length)
        {
            return null;
        }

        var cleaned = new string(text.Select(static c => char.IsControl(c) || c == '\uFFFD' ? '·' : c).ToArray());
        return cleaned.Length > Max ? cleaned[..Max] + "…" : cleaned;
    }

    public static IReadOnlyList<JwtHeaderNote> ReadHeaderNotes(string headerJson, int segmentCount)
    {
        using var document = JsonDocument.Parse(headerJson);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return [];
        }

        var notes = new List<JwtHeaderNote>();
        if (!TryGetString(root, "alg", out var alg))
        {
            notes.Add(new JwtHeaderNote("No alg. A JOSE header has to name an algorithm.", true));
        }
        else if (alg.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            notes.Add(new JwtHeaderNote(
                $"{alg} — Unsigned. Anyone can alter this token without detection.",
                true));
        }
        else if (DescribeAlgorithm(alg) is { } algorithm)
        {
            notes.Add(new JwtHeaderNote($"{alg} — {algorithm}", false));
        }

        if (TryGetString(root, "enc", out var enc))
        {
            if (segmentCount == 3)
            {
                notes.Add(new JwtHeaderNote(
                    "enc is a JWE header field. This token has 3 segments, so it is signed, not encrypted.",
                    true));
            }
            else if (DescribeEncryption(enc) is { } encryption)
            {
                notes.Add(new JwtHeaderNote($"{enc} — {encryption}", false));
            }
        }
        else if (segmentCount == 5)
        {
            notes.Add(new JwtHeaderNote(
                "No enc. A JWE header has to name the content encryption algorithm.",
                true));
        }

        if (TryGetString(root, "typ", out var typ) && DescribeType(typ) is { } type)
        {
            notes.Add(new JwtHeaderNote($"{typ} — {type}", false));
        }

        if (TryGetString(root, "cty", out var cty) && cty.Equals("JWT", StringComparison.OrdinalIgnoreCase))
        {
            notes.Add(new JwtHeaderNote("cty JWT means the payload is itself a compact JWT.", false));
        }

        if (TryGetString(root, "zip", out var zip) && zip.Equals("DEF", StringComparison.Ordinal))
        {
            notes.Add(new JwtHeaderNote("zip DEF means the plaintext is DEFLATE-compressed.", false));
        }

        return notes;
    }

    public static IReadOnlyList<JwtTimeNote> ReadTimeNotes(string payloadJson, DateTimeOffset now)
    {
        using var document = JsonDocument.Parse(payloadJson);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return [];
        }

        var notes = new List<JwtTimeNote>();
        foreach (var (claim, label) in TimeClaims)
        {
            if (!root.TryGetProperty(claim, out var value))
            {
                continue;
            }

            notes.Add(DescribeTime(claim, label, value, now));
        }

        foreach (var property in root.EnumerateObject())
        {
            if (TimeClaims.Any(claim => claim.Claim == property.Name) || !IsAdditionalTimeClaim(property.Name))
            {
                continue;
            }

            AddTimeValues(notes, property.Name, "Timestamp", property.Value, now);
        }

        return notes;
    }

    private static bool IsAdditionalTimeClaim(string name) =>
        name.EndsWith("_iat", StringComparison.Ordinal)
        || name.EndsWith("_exp", StringComparison.Ordinal)
        || name.EndsWith("_nbf", StringComparison.Ordinal);

    private static void AddTimeValues(
        List<JwtTimeNote> notes,
        string claim,
        string label,
        JsonElement value,
        DateTimeOffset now)
    {
        if (value.ValueKind != JsonValueKind.Array)
        {
            notes.Add(DescribeTime(claim, label, value, now));
            return;
        }

        var added = false;
        foreach (var item in value.EnumerateArray())
        {
            var note = DescribeTime(claim, label, item, now);
            if (notes.Any(existing => existing.Claim == note.Claim && existing.AbsoluteUtc == note.AbsoluteUtc && existing.Relative == note.Relative))
            {
                continue;
            }

            notes.Add(note);
            added = true;
        }

        if (!added)
        {
            notes.Add(new JwtTimeNote(claim, label, null, "Not a Unix timestamp.", JwtTimeTone.Warning, false));
        }
    }

    private static JwtSegment Segment(JwtSegmentRole role, string label, string text) =>
        new(role, label, text);

    private static JwtTimeNote DescribeTime(string claim, string label, JsonElement value, DateTimeOffset now)
    {
        if (!TryReadUnix(value, out var seconds, out var wasMilliseconds))
        {
            return new JwtTimeNote(claim, label, null, "Not a Unix timestamp.", JwtTimeTone.Warning, false);
        }

        DateTimeOffset instant;
        try
        {
            instant = DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return new JwtTimeNote(claim, label, null, "Unix timestamp is out of range.", JwtTimeTone.Warning, wasMilliseconds);
        }

        var absolute = instant.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        var delta = instant - now;
        return new JwtTimeNote(claim, label, absolute, DescribeDelta(claim, delta), ToneFor(claim, delta), wasMilliseconds);
    }

    private static bool TryReadUnix(JsonElement value, out long seconds, out bool wasMilliseconds)
    {
        wasMilliseconds = false;
        seconds = 0;
        long raw;

        switch (value.ValueKind)
        {
            case JsonValueKind.Number when value.TryGetInt64(out raw):
                break;
            case JsonValueKind.Number when value.TryGetDouble(out var number)
                && double.IsFinite(number)
                && number == Math.Truncate(number)
                && number is >= long.MinValue and <= long.MaxValue:
                raw = (long)number;
                break;
            case JsonValueKind.String when long.TryParse(
                value.GetString()?.Trim(),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out raw):
                break;
            default:
                return false;
        }

        if (raw > MillisecondThreshold)
        {
            wasMilliseconds = true;
            raw /= 1000;
        }

        seconds = raw;
        return true;
    }

    private static string DescribeDelta(string claim, TimeSpan delta)
    {
        var nowish = IsNow(delta);
        var duration = FormatDuration(delta);
        return claim switch
        {
            "exp" when nowish => "expires now",
            "exp" when delta > TimeSpan.Zero => $"expires in {duration}",
            "exp" => $"expired {duration} ago",
            "nbf" when nowish => "valid now",
            "nbf" when delta > TimeSpan.Zero => $"not valid for {duration}",
            "nbf" => $"valid since {duration} ago",
            "iat" when nowish => "issued just now",
            "iat" when delta > TimeSpan.Zero => $"issued {duration} in the future",
            "iat" => $"issued {duration} ago",
            "auth_time" when nowish => "authenticated just now",
            "auth_time" when delta > TimeSpan.Zero => $"authenticated {duration} in the future",
            "auth_time" => $"authenticated {duration} ago",
            _ when nowish => "just now",
            _ when delta > TimeSpan.Zero => $"{duration} in the future",
            _ => $"{duration} ago"
        };
    }

    private static JwtTimeTone ToneFor(string claim, TimeSpan delta)
    {
        var nowish = IsNow(delta);
        return claim switch
        {
            "exp" when !nowish && delta > TimeSpan.Zero => JwtTimeTone.Ok,
            "exp" when !nowish && delta < TimeSpan.Zero => JwtTimeTone.Danger,
            "exp" => JwtTimeTone.Warning,
            "nbf" when !nowish && delta > TimeSpan.Zero => JwtTimeTone.Warning,
            "nbf" => JwtTimeTone.Ok,
            "iat" or "auth_time" when !nowish && delta > TimeSpan.Zero => JwtTimeTone.Warning,
            _ when !nowish && delta > TimeSpan.Zero => JwtTimeTone.Warning,
            _ => JwtTimeTone.Neutral
        };
    }

    private static bool IsNow(TimeSpan delta) => delta.Duration() < TimeSpan.FromSeconds(1);

    private static string FormatDuration(TimeSpan span)
    {
        var abs = span.Duration();
        if (abs.TotalDays >= 365)
        {
            var days = (int)abs.TotalDays;
            var years = days / 365;
            var rest = days % 365;
            return rest == 0 ? $"{years}y" : $"{years}y {rest}d";
        }

        if (abs.TotalHours >= 48)
        {
            var days = (int)abs.TotalDays;
            var hours = abs.Hours;
            return hours == 0 ? $"{days}d" : $"{days}d {hours}h";
        }

        if (abs.TotalHours >= 1)
        {
            var hours = (int)abs.TotalHours;
            var minutes = abs.Minutes;
            return minutes == 0 ? $"{hours}h" : $"{hours}h {minutes}m";
        }

        if (abs.TotalMinutes >= 1)
        {
            var minutes = (int)abs.TotalMinutes;
            var seconds = abs.Seconds;
            if (seconds == 0 || minutes >= 10)
            {
                return $"{minutes}m";
            }

            return $"{minutes}m {seconds}s";
        }

        return $"{(int)abs.TotalSeconds}s";
    }

    private static bool TryGetString(JsonElement root, string name, out string value)
    {
        value = "";
        if (!root.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? "";
        return value.Length > 0;
    }

    private static string? DescribeAlgorithm(string alg) => alg switch
    {
        "HS256" => "HMAC using SHA-256. A shared secret, not an issuer public key.",
        "HS384" => "HMAC using SHA-384. A shared secret, not an issuer public key.",
        "HS512" => "HMAC using SHA-512. A shared secret, not an issuer public key.",
        "RS256" => "RSASSA-PKCS1-v1_5 using SHA-256.",
        "RS384" => "RSASSA-PKCS1-v1_5 using SHA-384.",
        "RS512" => "RSASSA-PKCS1-v1_5 using SHA-512.",
        "PS256" => "RSASSA-PSS using SHA-256.",
        "PS384" => "RSASSA-PSS using SHA-384.",
        "PS512" => "RSASSA-PSS using SHA-512.",
        "ES256" => "ECDSA using P-256 and SHA-256.",
        "ES384" => "ECDSA using P-384 and SHA-384.",
        "ES512" => "ECDSA using P-521 and SHA-512.",
        "EdDSA" => "Edwards-curve signature (Ed25519 or Ed448).",
        "RSA-OAEP" => "RSAES-OAEP using SHA-1 to encrypt the content key.",
        "RSA-OAEP-256" => "RSAES-OAEP using SHA-256 to encrypt the content key.",
        "RSA1_5" => "RSAES-PKCS1-v1_5 to encrypt the content key.",
        "dir" => "The shared symmetric key is used directly as the content key.",
        "A128KW" => "AES key wrap with a 128-bit key.",
        "A192KW" => "AES key wrap with a 192-bit key.",
        "A256KW" => "AES key wrap with a 256-bit key.",
        "A128GCMKW" => "AES-GCM key wrap with a 128-bit key.",
        "A192GCMKW" => "AES-GCM key wrap with a 192-bit key.",
        "A256GCMKW" => "AES-GCM key wrap with a 256-bit key.",
        "ECDH-ES" => "Elliptic-curve Diffie-Hellman directly agrees the content key.",
        "ECDH-ES+A128KW" => "ECDH-ES, then AES-128 key wrap.",
        "ECDH-ES+A192KW" => "ECDH-ES, then AES-192 key wrap.",
        "ECDH-ES+A256KW" => "ECDH-ES, then AES-256 key wrap.",
        _ => null
    };

    private static string? DescribeEncryption(string enc) => enc switch
    {
        "A128GCM" => "AES-128-GCM content encryption.",
        "A192GCM" => "AES-192-GCM content encryption.",
        "A256GCM" => "AES-256-GCM content encryption.",
        "A128CBC-HS256" => "AES-128-CBC with HMAC-SHA-256.",
        "A192CBC-HS384" => "AES-192-CBC with HMAC-SHA-384.",
        "A256CBC-HS512" => "AES-256-CBC with HMAC-SHA-512.",
        _ => null
    };

    private static string? DescribeType(string typ) => typ.ToLowerInvariant() switch
    {
        "at+jwt" or "application/at+jwt" => "Access token (RFC 9068), not an ID token.",
        "logout+jwt" => "Back-channel logout token.",
        "secevent+jwt" => "Security event token (RFC 8417).",
        "dpop+jwt" => "DPoP proof (RFC 9449).",
        _ => null
    };
}
