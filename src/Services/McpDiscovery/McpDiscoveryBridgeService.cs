using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;

namespace authstudio;

public class McpDiscoveryBridgeService(
    IPersistentSettingsRepository settingsRepository,
    NavigationManager navigationManager)
{
    public async Task ApplyToBuilderAsync(McpDiscoverySession session)
    {
        if (session.AuthorizationServerMetadata is null)
        {
            throw new InvalidOperationException("Discovery did not resolve authorization server metadata.");
        }

        var metadata = session.AuthorizationServerMetadata;
        var issuer = new IssuerModel
        {
            Issuer = metadata.Issuer,
            AuthorizeEndpoint = metadata.AuthorizationEndpoint,
            TokenEndpoint = metadata.TokenEndpoint,
            UserInfoEndpoint = metadata.UserInfoEndpoint,
            JwksUri = metadata.JwksUri,
            IntrospectionEndpoint = metadata.IntrospectionEndpoint,
            PushedAuthorizationRequestEndpoint = metadata.PushedAuthorizationRequestEndpoint,
            RequirePushedAuthorizationRequests = metadata.RequirePushedAuthorizationRequests,
            ClientIdMetadataDocumentSupported = metadata.ClientIdMetadataDocumentSupported,
            ConfigurationUri = session.AuthorizationServerMetadataUrl ?? ""
        };

        var authorizeParameters = await settingsRepository.GetAuthorizeParameterModelAsync()
            ?? new AuthorizeParameterModel();
        authorizeParameters.Resource = session.CanonicalResourceUri;
        authorizeParameters.UsePushedAuthorization = metadata.RequirePushedAuthorizationRequests;

        if (!string.IsNullOrWhiteSpace(session.SuggestedScope))
        {
            authorizeParameters.ScopeParameter = session.SuggestedScope;
        }

        var clientApp = await settingsRepository.GetClientAppModelAsync() ?? new ClientAppModel();
        if (CimdDefaults.ShouldDefaultClientId(clientApp.ClientId, metadata.ClientIdMetadataDocumentSupported))
        {
            clientApp.ClientId = CimdDefaults.GetDocumentUrl(navigationManager);
        }

        await settingsRepository.SetIssuerModelAsync(issuer);
        await settingsRepository.SetAuthorizeParameterModelAsync(authorizeParameters);
        await settingsRepository.SetClientAppModelAsync(clientApp);
    }
}

public interface IMcpDiscoveryRepository
{
    Task<McpDiscoverySession?> GetLastSessionAsync();
    Task SetLastSessionAsync(McpDiscoverySession session);
    Task<string?> GetLastMcpServerUrlAsync();
    Task SetLastMcpServerUrlAsync(string url);
}

public class LocalStorageMcpDiscoveryRepository(ILocalStorageService localStorageService) : IMcpDiscoveryRepository
{
    private const string SessionKey = "McpDiscoverySession";
    private const string UrlKey = "McpDiscoveryUrl";

    public Task<McpDiscoverySession?> GetLastSessionAsync() =>
        localStorageService.GetItemAsync<McpDiscoverySession?>(SessionKey).AsTask();

    public async Task SetLastSessionAsync(McpDiscoverySession session)
    {
        await localStorageService.SetItemAsync(SessionKey, session);
    }

    public Task<string?> GetLastMcpServerUrlAsync() =>
        localStorageService.GetItemAsync<string?>(UrlKey).AsTask();

    public async Task SetLastMcpServerUrlAsync(string url)
    {
        await localStorageService.SetItemAsync(UrlKey, url);
    }
}
