using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using authstudio;
using Blazored.LocalStorage;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddBlazoredLocalStorage();
builder.Services.AddScoped<OAuthBuilderActions>();
builder.Services.AddScoped<ClientAssertionService>();
builder.Services.AddScoped<JweDecryptionService>();
builder.Services.AddScoped<JwksService>();
builder.Services.AddScoped<JwtVerificationService>();
builder.Services.AddScoped<WorkspacePresetService>();
builder.Services.AddScoped<IWorkspaceSessionRepository, LocalStorageWorkspaceSessionRepository>();
builder.Services.AddScoped<IPersistentSettingsRepository, LocalStoragePersistentSettingsRepository>();
builder.Services.AddScoped<ITransientRepository, LocalStorageTransientRepository>();

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddHttpClient("AuthClient");

await builder.Build().RunAsync();
