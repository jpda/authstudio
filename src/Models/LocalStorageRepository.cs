using Blazored.LocalStorage;

namespace authstudio;

public interface IOperatingRepository
{
    public Task<IssuerModel> GetIssuerModelAsync();
    public Task<IssuerModel> SetIssuerModelAsync(IssuerModel issuerModel);
    public Task<ClientAppModel> GetClientAppModelAsync();
    public Task<ClientAppModel> SetClientAppModelAsync(ClientAppModel clientAppModel);
    public Task<PkceChallengeModel> GetPkceChallengeModelAsync();
    public Task<PkceChallengeModel> SetPkceChallengeModelAsync(PkceChallengeModel pkceChallengeModel);
    public Task<AuthorizeRequestModel> GetAuthorizeRequestModelAsync();
    public Task<AuthorizeRequestModel> SetAuthorizeRequestModelAsync(AuthorizeRequestModel authorizeRequestModel);
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

public class LocalStorageOperatingRepository : IOperatingRepository
{
    private readonly ILocalStorageService localStorageService;
    public LocalStorageOperatingRepository(ILocalStorageService localStorageService)
    {
        this.localStorageService = localStorageService;
    }

    public async Task<AuthorizeRequestModel> GetAuthorizeRequestModelAsync()
    {
        return await localStorageService.GetItemAsync<AuthorizeRequestModel>("AuthorizeRequestModel");
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

    public async Task<AuthorizeRequestModel> SetAuthorizeRequestModelAsync(AuthorizeRequestModel authorizeRequestModel)
    {
        await localStorageService.SetItemAsync("AuthorizeRequestModel", authorizeRequestModel);
        return authorizeRequestModel;
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