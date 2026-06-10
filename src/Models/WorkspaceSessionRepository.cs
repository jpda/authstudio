using Blazored.LocalStorage;

namespace authstudio;

public interface IWorkspaceSessionRepository
{
    Task<string?> GetLastClientAssertionAsync();
    Task SetLastClientAssertionAsync(string assertion);
    Task<string?> GetActivePresetAsync();
    Task SetActivePresetAsync(string preset);
    Task<string?> GetDecryptionKeyJwkAsync();
    Task SetDecryptionKeyJwkAsync(string jwk);
}

public class LocalStorageWorkspaceSessionRepository(ILocalStorageService localStorageService) : IWorkspaceSessionRepository
{
    private const string LastAssertionKey = "WorkspaceSession.LastClientAssertion";
    private const string ActivePresetKey = "WorkspaceSession.ActivePreset";
    private const string DecryptionKeyKey = "WorkspaceSession.DecryptionKeyJwk";

    public async Task<string?> GetLastClientAssertionAsync() =>
        await localStorageService.GetItemAsync<string?>(LastAssertionKey);

    public async Task SetLastClientAssertionAsync(string assertion)
    {
        await localStorageService.SetItemAsync(LastAssertionKey, assertion);
    }

    public async Task<string?> GetActivePresetAsync() =>
        await localStorageService.GetItemAsync<string?>(ActivePresetKey);

    public async Task SetActivePresetAsync(string preset)
    {
        await localStorageService.SetItemAsync(ActivePresetKey, preset);
    }

    public async Task<string?> GetDecryptionKeyJwkAsync() =>
        await localStorageService.GetItemAsync<string?>(DecryptionKeyKey);

    public async Task SetDecryptionKeyJwkAsync(string jwk)
    {
        await localStorageService.SetItemAsync(DecryptionKeyKey, jwk);
    }
}
