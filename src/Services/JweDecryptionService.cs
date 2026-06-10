using Microsoft.JSInterop;

namespace authstudio;

public class JweDecryptionService(IJSRuntime jsRuntime, CryptoInteropService cryptoInterop)
{
    public async Task<string> DecryptAsync(string jwe, string privateKeyJwkJson)
    {
        await cryptoInterop.EnsureReadyAsync();

        return await jsRuntime.InvokeAsync<string>(
            "authstudioCrypto.decryptJwe",
            jwe,
            privateKeyJwkJson);
    }
}
