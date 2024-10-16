using Blazored.LocalStorage;

namespace authstudio;

public interface IPersistentSettingsRepository
{
    public Task<IssuerModel> GetIssuerModelAsync();
    public Task<IssuerModel> SetIssuerModelAsync(IssuerModel issuerModel);
    public Task<ClientAppModel> GetClientAppModelAsync();
    public Task<ClientAppModel> SetClientAppModelAsync(ClientAppModel clientAppModel);
    public Task<PkceChallengeModel> GetPkceChallengeModelAsync();
    public Task<PkceChallengeModel> SetPkceChallengeModelAsync(PkceChallengeModel pkceChallengeModel);
    public Task<AuthorizeParameterModel> GetAuthorizeParameterModelAsync();
    public Task<AuthorizeParameterModel> SetAuthorizeParameterModelAsync(AuthorizeParameterModel authorizeParameterModel);
}

public interface ITransientRepository
{
    public Task<AuthorizeRequestModel> GetAuthorizeRequestModelAsync(string id);
    public Task<AuthorizeRequestModel> SetAuthorizeRequestModelAsync(AuthorizeRequestModel authorizeRequestModel);
    public Task DeleteAuthorizeRequestModelAsync(string id);
}

public class LocalStorageTransientRepository : ITransientRepository
{
    private readonly ILocalStorageService localStorageService;
    public LocalStorageTransientRepository(ILocalStorageService localStorageService)
    {
        this.localStorageService = localStorageService;
    }

    public async Task<AuthorizeRequestModel> GetAuthorizeRequestModelAsync(string id)
    {
        return await localStorageService.GetItemAsync<AuthorizeRequestModel>($"AuthorizeRequestModel-{id}");
    }

    public async Task<AuthorizeRequestModel> SetAuthorizeRequestModelAsync(AuthorizeRequestModel authorizeRequestModel)
    {
        await localStorageService.SetItemAsync($"AuthorizeRequestModel-{authorizeRequestModel.Id}", authorizeRequestModel);
        return authorizeRequestModel;
    }

    public async Task DeleteAuthorizeRequestModelAsync(string id)
    {
        await localStorageService.RemoveItemAsync($"AuthorizeRequestModel-{id}");
    }
}

public class LocalStoragePersistentSettingsRepository : IPersistentSettingsRepository
{
    private readonly ILocalStorageService localStorageService;
    public LocalStoragePersistentSettingsRepository(ILocalStorageService localStorageService)
    {
        this.localStorageService = localStorageService;
    }

    public async Task<AuthorizeParameterModel> GetAuthorizeParameterModelAsync()
    {
        return await localStorageService.GetItemAsync<AuthorizeParameterModel>("AuthorizeParameterModel");
    }

    public async Task<ClientAppModel> GetClientAppModelAsync()
    {
        return await localStorageService.GetItemAsync<ClientAppModel>("ClientAppModel");
    }

    public async Task<IssuerModel> GetIssuerModelAsync()
    {
        return await localStorageService.GetItemAsync<IssuerModel>("IssuerModel");
    }

    public async Task<PkceChallengeModel> GetPkceChallengeModelAsync()
    {
        return await localStorageService.GetItemAsync<PkceChallengeModel>("PkceChallengeModel");
    }

    public async Task<AuthorizeParameterModel> SetAuthorizeParameterModelAsync(AuthorizeParameterModel authorizeParameterModel)
    {
        await localStorageService.SetItemAsync("AuthorizeParameterModel", authorizeParameterModel);
        return authorizeParameterModel;
    }

    public async Task<ClientAppModel> SetClientAppModelAsync(ClientAppModel clientAppModel)
    {
        await localStorageService.SetItemAsync("ClientAppModel", clientAppModel);
        return clientAppModel;
    }

    public async Task<IssuerModel> SetIssuerModelAsync(IssuerModel issuerModel)
    {
        await localStorageService.SetItemAsync("IssuerModel", issuerModel);
        return issuerModel;
    }

    public async Task<PkceChallengeModel> SetPkceChallengeModelAsync(PkceChallengeModel pkceChallengeModel)
    {
        await localStorageService.SetItemAsync("PkceChallengeModel", pkceChallengeModel);
        return pkceChallengeModel;
    }
}