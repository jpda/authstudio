using Microsoft.JSInterop;

namespace authstudio;

public class JwtVerificationService(
    IJSRuntime jsRuntime,
    JwksService jwksService,
    IPersistentSettingsRepository settingsRepository,
    HttpClient http)
{
    private int _cryptoReady;

    private static readonly HashSet<string> SupportedAlgorithms = new(StringComparer.Ordinal)
    {
        "RS256", "RS384", "ES256", "ES384", "ES512"
    };

    public async Task<JwtVerificationResult> VerifyAsync(
        string jwt,
        IEnumerable<KeyValuePair<string, string>>? claims = null)
    {
        JwsHeaderInfo header;
        try
        {
            header = CompactToken.ParseJwsHeader(jwt);
        }
        catch (Exception ex)
        {
            return new JwtVerificationResult(JwtSignatureStatus.Error, ex.Message);
        }

        if (header.Alg.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return new JwtVerificationResult(
                JwtSignatureStatus.Unsigned,
                "Token uses alg=none (unsigned).");
        }

        if (IsSymmetricAlgorithm(header.Alg))
        {
            return new JwtVerificationResult(
                JwtSignatureStatus.UnsupportedAlgorithm,
                $"{header.Alg} is symmetric — issuer JWKS verification is not available.");
        }

        if (!SupportedAlgorithms.Contains(header.Alg))
        {
            return new JwtVerificationResult(
                JwtSignatureStatus.UnsupportedAlgorithm,
                $"Verification is not implemented for {header.Alg}.");
        }

        var jwksUri = await ResolveJwksUriAsync(claims);
        if (string.IsNullOrWhiteSpace(jwksUri))
        {
            return new JwtVerificationResult(
                JwtSignatureStatus.KeysUnavailable,
                "No JWKS URI on the saved issuer. Fetch discovery on the builder, or ensure the token has an iss claim.");
        }

        string? keyJson;
        try
        {
            keyJson = await jwksService.FindVerificationKeyJsonAsync(jwksUri, header.Kid, header.Alg);
        }
        catch (Exception ex)
        {
            return new JwtVerificationResult(
                JwtSignatureStatus.Error,
                $"Could not fetch JWKS: {ex.Message}",
                jwksUri);
        }

        if (keyJson is null)
        {
            var kidMessage = string.IsNullOrEmpty(header.Kid)
                ? $"No unique signing key for alg={header.Alg} in JWKS."
                : $"kid '{header.Kid}' not found in issuer JWKS for alg={header.Alg}.";

            return new JwtVerificationResult(
                JwtSignatureStatus.KeyNotFound,
                kidMessage,
                jwksUri,
                header.Kid);
        }

        if (Interlocked.CompareExchange(ref _cryptoReady, 1, 0) == 0)
        {
            await jsRuntime.InvokeVoidAsync("authstudioLoadCrypto");
        }

        try
        {
            var valid = await jsRuntime.InvokeAsync<bool>(
                "authstudioCrypto.verifyJwt",
                jwt,
                keyJson,
                header.Alg);

            using var keyDocument = System.Text.Json.JsonDocument.Parse(keyJson);
            var matchedKid = keyDocument.RootElement.TryGetProperty("kid", out var kidElement)
                ? kidElement.GetString()
                : header.Kid;

            return valid
                ? new JwtVerificationResult(
                    JwtSignatureStatus.Valid,
                    $"Signature valid using issuer JWKS key {(string.IsNullOrEmpty(matchedKid) ? "" : $"kid={matchedKid} ")}({header.Alg}).",
                    jwksUri,
                    matchedKid)
                : new JwtVerificationResult(
                    JwtSignatureStatus.Invalid,
                    $"Signature does not match issuer JWKS key {(string.IsNullOrEmpty(matchedKid) ? "" : $"kid={matchedKid} ")}({header.Alg}).",
                    jwksUri,
                    matchedKid);
        }
        catch (Exception ex)
        {
            return new JwtVerificationResult(
                JwtSignatureStatus.Error,
                ex.Message,
                jwksUri,
                header.Kid);
        }
    }

    private async Task<string?> ResolveJwksUriAsync(IEnumerable<KeyValuePair<string, string>>? claims)
    {
        var issuer = await settingsRepository.GetIssuerModelAsync();
        if (!string.IsNullOrWhiteSpace(issuer?.JwksUri))
        {
            return issuer.JwksUri;
        }

        var iss = claims is null ? null : CompactToken.GetClaimValue(claims, "iss");
        if (string.IsNullOrWhiteSpace(iss))
        {
            return null;
        }

        try
        {
            var config = await OpenIdDiscovery.FetchAsync(http, iss, "");
            return string.IsNullOrWhiteSpace(config.JwksUri) ? null : config.JwksUri;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsSymmetricAlgorithm(string alg) =>
        alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase);
}
