using System.Text;

namespace authstudio.Tests;

public class JwtPresentationTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 16, 0, 0, TimeSpan.Zero);

    private const string SampleJws =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlbW8tMSJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZSJ9." +
        "signature";

    [Theory]
    [InlineData("  eyJ.aaa.bbb  ", "eyJ.aaa.bbb")]
    [InlineData("\"eyJ.aaa.bbb\"", "eyJ.aaa.bbb")]
    [InlineData("Bearer eyJ.aaa.bbb", "eyJ.aaa.bbb")]
    [InlineData("bearer\neyJ.aaa.bbb", "eyJ.aaa.bbb")]
    [InlineData("eyJ.\naaa.\nbbb", "eyJ.aaa.bbb")]
    public void Normalize_strips_wrapping_and_whitespace(string input, string expected)
    {
        Assert.Equal(expected, JwtPresentation.Normalize(input));
    }

    [Fact]
    public void Split_labels_signed_and_encrypted_tokens()
    {
        var signed = JwtPresentation.Split(SampleJws);
        Assert.Equal(["Header", "Payload", "Signature"], signed.Select(segment => segment.Label));
        Assert.Null(JwtPresentation.StructureMessage(signed.Count));

        var encrypted = JwtPresentation.Split("a.b.c.d.e");
        Assert.Equal(
            ["Header", "Encrypted key", "IV", "Ciphertext", "Auth tag"],
            encrypted.Select(segment => segment.Label));
        Assert.Null(JwtPresentation.StructureMessage(encrypted.Count));
    }

    [Fact]
    public void StructureMessage_explains_unexpected_segment_counts()
    {
        Assert.Contains("signature", JwtPresentation.StructureMessage(2), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("4", JwtPresentation.StructureMessage(4));
        Assert.Contains("three", JwtPresentation.StructureMessage(1), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecodeJson_preserves_claim_order()
    {
        var json = """{"sub":"1","iss":"https://issuer.example"}""";
        var encoded = JwtEncoding.Base64UrlEncode(Encoding.UTF8.GetBytes(json));

        var decoded = JwtPresentation.DecodeJson(encoded);

        Assert.Null(decoded.Error);
        Assert.True(decoded.Json!.IndexOf("sub", StringComparison.Ordinal) < decoded.Json.IndexOf("iss", StringComparison.Ordinal));
    }

    [Fact]
    public void DecodeJson_names_the_bad_character()
    {
        var decoded = JwtPresentation.DecodeJson("eyJ%hbGc");

        Assert.Null(decoded.Json);
        Assert.Equal(
            "Not base64url: '%' at position 4. Segments use only A–Z, a–z, 0–9, - and _.",
            decoded.Error);
    }

    [Fact]
    public void DecodeJson_flags_truncated_segments()
    {
        var decoded = JwtPresentation.DecodeJson("eyJhb");

        Assert.Null(decoded.Json);
        Assert.Contains("truncated", decoded.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void DecodeJson_previews_non_json_content()
    {
        var encoded = JwtEncoding.Base64UrlEncode(Encoding.UTF8.GetBytes("hello world"));

        var decoded = JwtPresentation.DecodeJson(encoded);

        Assert.Null(decoded.Json);
        Assert.Equal("Decodes from base64url, but the result is not JSON: “hello world”", decoded.Error);
    }

    [Fact]
    public void DecodeJson_describes_binary_and_single_character_segments()
    {
        Assert.Equal(
            "Decodes from base64url to 2 bytes of binary data, not JSON text.",
            JwtPresentation.DecodeJson("not").Error);
        Assert.Equal(
            "Not base64url: 1 character cannot be a complete encoding. The token may be truncated.",
            JwtPresentation.DecodeJson("a").Error);
    }

    [Fact]
    public void ReadHeaderNotes_describes_algorithms_and_warnings()
    {
        var es256 = JwtPresentation.ReadHeaderNotes("""{"alg":"ES256","typ":"JWT"}""", 3);
        Assert.Contains(es256, note => note.Text.Contains("P-256", StringComparison.Ordinal) && !note.IsWarning);

        var unsigned = JwtPresentation.ReadHeaderNotes("""{"alg":"none"}""", 3);
        Assert.Contains(unsigned, note => note.IsWarning && note.Text.Contains("Unsigned", StringComparison.Ordinal));

        var accessToken = JwtPresentation.ReadHeaderNotes("""{"alg":"RS256","typ":"at+jwt"}""", 3);
        Assert.Contains(accessToken, note => note.Text.Contains("RFC 9068", StringComparison.Ordinal));

        var jwe = JwtPresentation.ReadHeaderNotes("""{"alg":"RSA-OAEP-256","enc":"A256GCM"}""", 5);
        Assert.Contains(jwe, note => note.Text.Contains("SHA-256", StringComparison.Ordinal));
        Assert.Contains(jwe, note => note.Text.Contains("AES-256-GCM", StringComparison.Ordinal));

        var missingEnc = JwtPresentation.ReadHeaderNotes("""{"alg":"RSA-OAEP-256"}""", 5);
        Assert.Contains(missingEnc, note => note.IsWarning && note.Text.Contains("No enc", StringComparison.Ordinal));

        var nested = JwtPresentation.ReadHeaderNotes("""{"alg":"RS256","cty":"JWT"}""", 3);
        Assert.Contains(nested, note => note.Text.Contains("compact JWT", StringComparison.Ordinal));
    }

    [Fact]
    public void ReadTimeNotes_describes_standard_time_claims()
    {
        var payload = $$"""
            {
              "exp": {{ToUnix(Now.AddMinutes(14))}},
              "iat": {{ToUnix(Now.AddMinutes(-3))}},
              "nbf": {{ToUnix(Now.AddMinutes(5))}},
              "auth_time": {{ToUnix(Now.AddMinutes(-20))}}
            }
            """;

        var notes = JwtPresentation.ReadTimeNotes(payload, Now);

        Assert.Equal(["iat", "nbf", "auth_time", "exp"], notes.Select(note => note.Claim));
        Assert.Equal("issued 3m ago", Note(notes, "iat").Relative);
        Assert.Equal(JwtTimeTone.Neutral, Note(notes, "iat").Tone);
        Assert.Equal("not valid for 5m", Note(notes, "nbf").Relative);
        Assert.Equal(JwtTimeTone.Warning, Note(notes, "nbf").Tone);
        Assert.Equal("authenticated 20m ago", Note(notes, "auth_time").Relative);
        Assert.Equal("expires in 14m", Note(notes, "exp").Relative);
        Assert.Equal(JwtTimeTone.Ok, Note(notes, "exp").Tone);
        Assert.Equal("2026-10-30 16:14:00 UTC", Note(notes, "exp").AbsoluteUtc);
    }

    [Fact]
    public void ReadTimeNotes_covers_boundaries_and_bad_values()
    {
        var payload = $$"""
            {
              "exp": {{ToUnix(Now)}},
              "iat": "{{ToUnix(Now.AddSeconds(45))}}",
              "nbf": {{ToUnix(Now.AddMinutes(-5))}},
              "auth_time": "nope"
            }
            """;

        var notes = JwtPresentation.ReadTimeNotes(payload, Now);

        Assert.Equal("expires now", Note(notes, "exp").Relative);
        Assert.Equal(JwtTimeTone.Warning, Note(notes, "exp").Tone);
        Assert.Equal("issued 45s in the future", Note(notes, "iat").Relative);
        Assert.Equal(JwtTimeTone.Warning, Note(notes, "iat").Tone);
        Assert.Equal("valid since 5m ago", Note(notes, "nbf").Relative);
        Assert.Equal(JwtTimeTone.Ok, Note(notes, "nbf").Tone);
        Assert.Equal("Not a Unix timestamp.", Note(notes, "auth_time").Relative);
        Assert.Null(Note(notes, "auth_time").AbsoluteUtc);
    }

    [Fact]
    public void ReadTimeNotes_formats_longer_spans_and_milliseconds()
    {
        var payload = $$"""
            {
              "exp": {{ToUnix(Now.AddHours(3).AddMinutes(12))}},
              "iat": {{ToUnix(Now.AddDays(-4).AddHours(-2))}},
              "nbf": {{ToUnix(Now.AddDays(-400))}},
              "auth_time": {{Now.ToUnixTimeMilliseconds()}}
            }
            """;

        var notes = JwtPresentation.ReadTimeNotes(payload, Now);

        Assert.Equal("expires in 3h 12m", Note(notes, "exp").Relative);
        Assert.Equal("issued 4d 2h ago", Note(notes, "iat").Relative);
        Assert.Equal("valid since 1y 35d ago", Note(notes, "nbf").Relative);
        Assert.True(Note(notes, "auth_time").WasMilliseconds);
        Assert.Equal("authenticated just now", Note(notes, "auth_time").Relative);
        Assert.Equal("2026-10-30 16:00:00 UTC", Note(notes, "auth_time").AbsoluteUtc);
    }

    [Fact]
    public void ReadTimeNotes_decodes_extra_timestamp_claims()
    {
        var instant = ToUnix(Now.AddHours(-50));
        var payload = $$"""
            {
              "ext_iat": ["{{instant}}", "{{instant}}"],
              "role_iat": "{{instant}}",
              "at_hash": "SmMtOYmNphon19Z_TDeF6Q"
            }
            """;

        var notes = JwtPresentation.ReadTimeNotes(payload, Now);

        Assert.Equal(["ext_iat", "role_iat"], notes.Select(note => note.Claim));
        Assert.All(notes, note => Assert.Equal("2d 2h ago", note.Relative));
        Assert.All(notes, note => Assert.Equal(JwtTimeTone.Neutral, note.Tone));
        Assert.Equal("Timestamp", notes[0].Label);
    }

    [Fact]
    public void ReadTimeNotes_marks_expired_tokens()
    {
        var payload = $$"""{"exp": {{ToUnix(Now.AddMinutes(-2))}}}""";
        var note = Assert.Single(JwtPresentation.ReadTimeNotes(payload, Now));

        Assert.Equal("expired 2m ago", note.Relative);
        Assert.Equal(JwtTimeTone.Danger, note.Tone);
    }

    private static JwtTimeNote Note(IReadOnlyList<JwtTimeNote> notes, string claim) =>
        notes.Single(note => note.Claim == claim);

    private static long ToUnix(DateTimeOffset instant) => instant.ToUnixTimeSeconds();
}
