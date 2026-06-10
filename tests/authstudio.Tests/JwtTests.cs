namespace authstudio.Tests;

public class JwtEncodingTests
{
    [Fact]
    public void Base64UrlEncode_round_trips()
    {
        var data = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"u8.ToArray();
        var encoded = JwtEncoding.Base64UrlEncode(data);

        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.Equal(data, JwtEncoding.Base64UrlDecode(encoded));
    }

    [Fact]
    public void Base64UrlDecode_handles_padding()
    {
        var encoded = "YQ";
        Assert.Equal("a"u8.ToArray(), JwtEncoding.Base64UrlDecode(encoded));
    }
}

public class JwtDecoderTests
{
    private const string SampleJwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlbW8tMSJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZSJ9." +
        "signature";

    [Fact]
    public void Decode_parses_header_and_payload()
    {
        var parts = JwtDecoder.Decode(SampleJwt);

        Assert.Contains("\"alg\": \"ES256\"", parts.Header);
        Assert.Contains("\"kid\": \"demo-1\"", parts.Header);
        Assert.Contains("\"sub\": \"1234567890\"", parts.Payload);
        Assert.Equal("signature", parts.Signature);
    }
}

public class CompactTokenTests
{
    private const string SampleJws =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlbW8tMSJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZSJ9." +
        "signature";

    private const string SampleJwe =
        "eyJhbGciOiJSU0EtT0FFUCJ9." +
        "eyJlbmMiOiJBMjU2R0NNIn0." +
        "YQ.YQ.YQ";

    [Theory]
    [InlineData("", CompactTokenKind.Invalid)]
    [InlineData("a.b", CompactTokenKind.Invalid)]
    [InlineData(SampleJws, CompactTokenKind.Jws)]
    [InlineData(SampleJwe, CompactTokenKind.Jwe)]
    public void GetKind_classifies_tokens(string token, CompactTokenKind expected)
    {
        Assert.Equal(expected, CompactToken.GetKind(token));
    }

    [Fact]
    public void ParseJwsHeader_reads_standard_fields()
    {
        var header = CompactToken.ParseJwsHeader(SampleJws);

        Assert.Equal("ES256", header.Alg);
        Assert.Equal("demo-1", header.Kid);
        Assert.Equal("JWT", header.Typ);
    }

    [Fact]
    public void ParseClaimsFromToken_reads_payload_claims()
    {
        var claims = CompactToken.ParseClaimsFromToken(SampleJws);

        Assert.Equal("1234567890", CompactToken.GetClaimValue(claims, "sub"));
        Assert.Equal("https://issuer.example", CompactToken.GetClaimValue(claims, "iss"));
    }
}
