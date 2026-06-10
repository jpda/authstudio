using Microsoft.JSInterop;

namespace authstudio;

public class CryptoInteropService(IJSRuntime jsRuntime)
{
    private readonly object _gate = new();
    private Task? _ready;

    public Task EnsureReadyAsync()
    {
        lock (_gate)
        {
            return _ready ??= LoadAsync();
        }
    }

    private async Task LoadAsync()
    {
        try
        {
            await jsRuntime.InvokeVoidAsync("authstudioLoadCrypto");
        }
        catch
        {
            lock (_gate)
            {
                _ready = null;
            }

            throw;
        }
    }
}
