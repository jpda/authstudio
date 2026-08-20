using System.Net;
using System.Text.Json;

namespace authstudio;

public enum CimdSampleBucket
{
    Valid,
    InvalidDocument,
    FetchError,
    SecurityPolicy
}

public record CimdSample(
    string Id,
    CimdSampleBucket Bucket,
    string Title,
    string Path,
    string SpecRef,
    string Description,
    bool IsJson = true);

public static class CimdSampleCatalog
{
    public const string SpecUri =
        "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02";

    public static IReadOnlyList<CimdSample> All { get; } =
    [
        new("public", CimdSampleBucket.Valid, "Public client", "client.json",
            "§4, §8.2",
            "Hosted public CIMD for this origin (client.json or local.json). Send to builder to use it as client_id."),
        new("private", CimdSampleBucket.Valid, "private_key_jwt client", "private-client.json",
            "§4.1, §8.2",
            "Hosted confidential CIMD for this origin. Send to builder also loads the illustrative signing key."),

        new("missing-client-id", CimdSampleBucket.InvalidDocument, "Missing client_id",
            "cimd-samples/missing-client-id.json", "§4",
            "The document MUST contain a client_id that matches the fetch URL."),
        new("client-id-mismatch", CimdSampleBucket.InvalidDocument, "client_id does not match URL",
            "cimd-samples/client-id-mismatch.json", "§4",
            "Comparisons MUST use simple string comparison against the URL that was fetched."),
        new("http-client-id", CimdSampleBucket.InvalidDocument, "Non-https client_id",
            "cimd-samples/http-client-id.json", "§3",
            "A Client Identifier URL MUST use the https scheme."),
        new("userinfo-client-id", CimdSampleBucket.InvalidDocument, "client_id with userinfo",
            "cimd-samples/userinfo-client-id.json", "§3",
            "A Client Identifier URL MUST NOT contain a userinfo component."),
        new("dot-path-client-id", CimdSampleBucket.InvalidDocument, "Dot path segments",
            "cimd-samples/dot-path-client-id.json", "§3",
            "MUST NOT contain single-dot or double-dot path components."),
        new("fragment-client-id", CimdSampleBucket.InvalidDocument, "client_id with fragment",
            "cimd-samples/fragment-client-id.json", "§3",
            "A Client Identifier URL MUST NOT contain a fragment component."),
        new("client-secret-basic", CimdSampleBucket.InvalidDocument, "Shared-secret auth method",
            "cimd-samples/client-secret-basic.json", "§4.1",
            "token_endpoint_auth_method MUST NOT be client_secret_basic, client_secret_post, or client_secret_jwt."),
        new("client-secret-field", CimdSampleBucket.InvalidDocument, "client_secret present",
            "cimd-samples/client-secret-field.json", "§4.1",
            "client_secret and client_secret_expires_at MUST NOT be used."),
        new("private-key-in-jwks", CimdSampleBucket.InvalidDocument, "Private key in jwks",
            "cimd-samples/private-key-in-jwks.json", "§4.1",
            "Only public keys are permitted. Private material such as d MUST NOT appear."),
        new("malformed-json", CimdSampleBucket.InvalidDocument, "Malformed JSON",
            "cimd-samples/malformed.json", "§4",
            "The document must be JSON as defined by RFC 8259.", IsJson: false),

        new("not-json", CimdSampleBucket.FetchError, "Non-JSON body",
            "cimd-samples/not-json.txt", "§4, §5",
            "The response must be JSON (application/*+json is allowed). This file is plain text.",
            IsJson: false),
        new("oversized", CimdSampleBucket.FetchError, "Larger than 5 KiB",
            "cimd-samples/oversized.json", "§8.7",
            "Servers SHOULD stop reading after about 5 kilobytes and treat the document as an error."),

        new("ssrf-loopback-jwks", CimdSampleBucket.SecurityPolicy, "Loopback jwks_uri",
            "cimd-samples/ssrf-loopback-jwks.json", "§8.6",
            "Servers MUST NOT fetch URLs in the document that resolve to special-use addresses (RFC 6890)."),
        new("ssrf-link-local-logo", CimdSampleBucket.SecurityPolicy, "Link-local logo_uri",
            "cimd-samples/ssrf-link-local-logo.json", "§8.6",
            "Metadata URIs that point at 169.254.169.254 are a classic cloud-metadata SSRF probe."),
        new("javascript-logo", CimdSampleBucket.SecurityPolicy, "javascript: logo_uri",
            "cimd-samples/javascript-logo.json", "§8.6",
            "Servers SHOULD only fetch or parse URLs with known, supported schemes."),
        new("file-jwks", CimdSampleBucket.SecurityPolicy, "file: jwks_uri",
            "cimd-samples/file-jwks.json", "§8.6",
            "Non-http(s) schemes increase SSRF risk if the server tries to resolve them.")
    ];

    public static string GetHostedPath(CimdSample sample, Uri baseUri) => sample.Id switch
    {
        "public" => CimdDefaults.GetDocumentPath(baseUri),
        "private" => CimdDefaults.GetPrivateClientDocumentPath(baseUri),
        _ => sample.Path
    };
}

public static class CimdLinter
{
    public const int RecommendedMaxBytes = 5 * 1024;

    private static readonly HashSet<string> ForbiddenAuthMethods = new(StringComparer.Ordinal)
    {
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt"
    };

    private static readonly HashSet<string> PrivateJwkParameters = new(StringComparer.Ordinal)
    {
        "d", "p", "q", "dp", "dq", "qi", "oth", "k"
    };

    private static readonly string[] UriFields =
    [
        "client_uri", "logo_uri", "policy_uri", "tos_uri", "jwks_uri", "initiate_login_uri"
    ];

    public static IReadOnlyList<ComplianceCheck> Lint(string body, string? documentUrl = null)
    {
        var checks = new List<ComplianceCheck>();
        var bytes = System.Text.Encoding.UTF8.GetByteCount(body);

        if (bytes > RecommendedMaxBytes)
        {
            checks.Add(Fail("size", "Response size",
                $"Document is {bytes} bytes. Draft-02 recommends treating more than {RecommendedMaxBytes} bytes as an error.",
                "§8.7"));
        }
        else
        {
            checks.Add(Pass("size", "Response size",
                $"{bytes} bytes (under the 5 KiB recommendation).", "§8.7"));
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException ex)
        {
            checks.Add(Fail("json", "JSON document", ex.Message, "§4"));
            return checks;
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                checks.Add(Fail("object", "JSON object",
                    $"Root value is {document.RootElement.ValueKind}, not an object.", "§4"));
                return checks;
            }

            checks.Add(Pass("json", "JSON document", "Parsed as a JSON object.", "§4"));
            LintObject(document.RootElement, documentUrl, checks);
        }

        return checks;
    }

    private static void LintObject(JsonElement root, string? documentUrl, List<ComplianceCheck> checks)
    {
        if (!root.TryGetProperty("client_id", out var clientIdElement))
        {
            checks.Add(Fail("client-id", "client_id", "Property is missing.", "§4"));
        }
        else if (clientIdElement.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(clientIdElement.GetString()))
        {
            checks.Add(Fail("client-id", "client_id", "Must be a non-empty string.", "§4"));
        }
        else
        {
            var clientId = clientIdElement.GetString()!;
            LintClientIdentifierUrl(clientId, documentUrl, checks);
        }

        if (root.TryGetProperty("client_secret", out _)
            || root.TryGetProperty("client_secret_expires_at", out _))
        {
            checks.Add(Fail("client-secret", "Shared secret fields",
                "client_secret and client_secret_expires_at MUST NOT be used.", "§4.1"));
        }

        if (root.TryGetProperty("token_endpoint_auth_method", out var authMethod)
            && authMethod.ValueKind == JsonValueKind.String
            && ForbiddenAuthMethods.Contains(authMethod.GetString() ?? ""))
        {
            checks.Add(Fail("auth-method", "token_endpoint_auth_method",
                $"\"{authMethod.GetString()}\" is a shared-secret method and MUST NOT appear in a CIMD.",
                "§4.1"));
        }

        if (root.TryGetProperty("jwks", out var jwks))
        {
            LintJwks(jwks, checks);
        }

        if (root.TryGetProperty("redirect_uris", out var redirectUris))
        {
            LintRedirectUris(redirectUris, checks);
        }

        foreach (var name in UriFields)
        {
            if (root.TryGetProperty(name, out var uri) && uri.ValueKind == JsonValueKind.String)
            {
                LintReferencedUri(name, uri.GetString(), checks);
            }
        }
    }

    private static void LintClientIdentifierUrl(string clientId, string? documentUrl, List<ComplianceCheck> checks)
    {
        if (!string.IsNullOrWhiteSpace(documentUrl)
            && !string.Equals(clientId, documentUrl, StringComparison.Ordinal))
        {
            checks.Add(Fail("client-id-match", "client_id match",
                "client_id MUST match the fetch URL using simple string comparison.", "§4"));
        }

        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var uri))
        {
            checks.Add(Fail("client-id-url", "Client Identifier URL",
                "client_id is not an absolute URI.", "§3"));
            return;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            checks.Add(Fail("client-id-https", "https scheme",
                $"Scheme is \"{uri.Scheme}\"; a Client Identifier URL MUST use https.", "§3"));
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            checks.Add(Fail("client-id-userinfo", "userinfo",
                "A Client Identifier URL MUST NOT contain a userinfo component.", "§3"));
        }

        if (string.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath == "/")
        {
            checks.Add(Warn("client-id-path", "path",
                "MUST contain a path component. A path of / is NOT RECOMMENDED.", "§3"));
        }

        if (HasDotPathSegments(clientId))
        {
            checks.Add(Fail("client-id-dots", "dot path segments",
                "MUST NOT contain single-dot or double-dot path components.", "§3"));
        }

        if (!string.IsNullOrEmpty(uri.Query))
        {
            checks.Add(Warn("client-id-query", "query",
                "A Client Identifier URL SHOULD NOT contain a query component.", "§3"));
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            checks.Add(Fail("client-id-fragment", "fragment",
                "A Client Identifier URL MUST NOT contain a fragment component.", "§3"));
        }
    }

    private static void LintJwks(JsonElement jwks, List<ComplianceCheck> checks)
    {
        if (jwks.ValueKind != JsonValueKind.Object
            || !jwks.TryGetProperty("keys", out var keys)
            || keys.ValueKind != JsonValueKind.Array)
        {
            checks.Add(Fail("jwks", "jwks", "jwks must be a JWK Set object with a keys array.", "§4.1"));
            return;
        }

        foreach (var key in keys.EnumerateArray())
        {
            if (key.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var property in key.EnumerateObject())
            {
                if (PrivateJwkParameters.Contains(property.Name))
                {
                    checks.Add(Fail("jwks-private", "Private key material",
                        $"JWK contains \"{property.Name}\". Only public keys are permitted.", "§4.1"));
                    return;
                }
            }
        }
    }

    private static void LintRedirectUris(JsonElement redirectUris, List<ComplianceCheck> checks)
    {
        if (redirectUris.ValueKind != JsonValueKind.Array)
        {
            checks.Add(Fail("redirect-uris", "redirect_uris", "Must be an array of URI strings.", "RFC 7591"));
            return;
        }

        foreach (var item in redirectUris.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || !Uri.TryCreate(item.GetString(), UriKind.Absolute, out var uri))
            {
                checks.Add(Fail("redirect-uris", "redirect_uris",
                    "Each redirect URI must be an absolute URI string.", "RFC 7591 / RFC 9700"));
                return;
            }

            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                checks.Add(Fail("redirect-fragment", "redirect_uris fragment",
                    "Redirect URIs must not contain a fragment.", "RFC 6749"));
                return;
            }

            LintReferencedUri("redirect_uris", uri.ToString(), checks);
        }
    }

    private static void LintReferencedUri(string field, string? value, List<ComplianceCheck> checks)
    {
        if (string.IsNullOrWhiteSpace(value) || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            checks.Add(Fail($"{field}-scheme", field,
                $"Scheme \"{uri.Scheme}:\" should not be fetched. Stick to http(s).", "§8.6"));
            return;
        }

        if (IsSpecialUseHost(uri.Host))
        {
            checks.Add(Fail($"{field}-ssrf", field,
                $"Host \"{uri.Host}\" is a special-use or loopback address. Servers MUST NOT fetch it.",
                "§8.6 / RFC 6890"));
        }
    }

    private static bool HasDotPathSegments(string clientId)
    {
        var path = clientId;
        var scheme = clientId.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            var pathStart = clientId.IndexOf('/', scheme + 3);
            if (pathStart < 0)
            {
                return false;
            }

            var query = clientId.IndexOfAny(['?', '#'], pathStart);
            path = query >= 0 ? clientId[pathStart..query] : clientId[pathStart..];
        }

        return path.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Any(segment => segment is "." or "..");
    }

    private static bool IsSpecialUseHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host.Trim('[', ']'), out var address))
        {
            return false;
        }

        return address.Equals(IPAddress.Loopback)
            || address.Equals(IPAddress.IPv6Loopback)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || IsPrivateOrLinkLocal(address);
    }

    private static bool IsPrivateOrLinkLocal(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
        {
            return bytes[0] == 10
                || bytes[0] == 127
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254)
                || bytes[0] == 0;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && bytes.Length == 16)
        {
            return (bytes[0] & 0xfe) == 0xfc
                || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80);
        }

        return false;
    }

    private static ComplianceCheck Pass(string id, string title, string message, string spec) =>
        new(id, title, DiscoveryStepStatus.Success, message, spec);

    private static ComplianceCheck Warn(string id, string title, string message, string spec) =>
        new(id, title, DiscoveryStepStatus.Warning, message, spec);

    private static ComplianceCheck Fail(string id, string title, string message, string spec) =>
        new(id, title, DiscoveryStepStatus.Failed, message, spec);
}
