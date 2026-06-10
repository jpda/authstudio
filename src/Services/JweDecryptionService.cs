using Microsoft.JSInterop;

namespace authstudio;

public class JweDecryptionService(IJSRuntime jsRuntime)
{
    private int _cryptoReady;

    public async Task<string> DecryptAsync(string jwe, string privateKeyJwkJson)
    {
        if (Interlocked.CompareExchange(ref _cryptoReady, 1, 0) == 0)
        {
            await jsRuntime.InvokeVoidAsync("authstudioLoadCrypto");
        }

        return await jsRuntime.InvokeAsync<string>(
            "authstudioCrypto.decryptJwe",
            jwe,
            privateKeyJwkJson);
    }
}
