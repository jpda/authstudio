using Microsoft.AspNetCore.Components;

namespace authstudio;

public enum WorkspacePreset
{
    Custom,
    PublicCimd,
    PrivateCimd
}

public class WorkspacePresetService(
    NavigationManager navigationManager,
    IPersistentSettingsRepository settingsRepository,
    IWorkspaceSessionRepository sessionRepository,
    HttpClient http)
{
    public async Task<WorkspacePreset> GetActivePresetAsync()
    {
        var name = await sessionRepository.GetActivePresetAsync();
        return Enum.TryParse<WorkspacePreset>(name, out var preset) ? preset : WorkspacePreset.Custom;
    }

    public async Task<ClientAppModel> ApplyPublicCimdAsync(ClientAppModel clientApp)
    {
        clientApp.ClientId = CimdDefaults.GetDocumentUrl(navigationManager);
        if (clientApp.TokenAuthMethod == TokenClientAuthMethod.PrivateKeyJwt)
        {
            clientApp.TokenAuthMethod = TokenClientAuthMethod.None;
            clientApp.SigningPrivateKeyJwk = "";
        }

        await settingsRepository.SetClientAppModelAsync(clientApp);
        await sessionRepository.SetActivePresetAsync(WorkspacePreset.PublicCimd.ToString());
        return clientApp;
    }

    public async Task<ClientAppModel> ApplyPrivateCimdAsync(ClientAppModel clientApp)
    {
        clientApp.ClientId = CimdDefaults.GetPrivateClientDocumentUrl(navigationManager);
        clientApp.TokenAuthMethod = TokenClientAuthMethod.PrivateKeyJwt;
        clientApp.SigningAlgorithm = "ES256";
        clientApp.ClientSecret = "";

        if (string.IsNullOrWhiteSpace(clientApp.SigningPrivateKeyJwk))
        {
            clientApp.SigningPrivateKeyJwk = await http.GetStringAsync(
                CimdDefaults.GetSigningKeyDocumentUrl(navigationManager));
        }

        await settingsRepository.SetClientAppModelAsync(clientApp);
        await sessionRepository.SetActivePresetAsync(WorkspacePreset.PrivateCimd.ToString());
        return clientApp;
    }

    public async Task MarkCustomAsync()
    {
        await sessionRepository.SetActivePresetAsync(WorkspacePreset.Custom.ToString());
    }
}
