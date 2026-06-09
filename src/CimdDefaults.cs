using Microsoft.AspNetCore.Components;

namespace authstudio;

public static class CimdDefaults
{
    public static string GetDocumentPath(Uri baseUri)
    {
        return IsLocalHost(baseUri) ? "local.json" : "client.json";
    }

    public static string GetPrivateClientDocumentPath(Uri baseUri)
    {
        return IsLocalHost(baseUri) ? "private-local.json" : "private-client.json";
    }

    public static string GetDocumentUrl(NavigationManager navigationManager)
    {
        return navigationManager.ToAbsoluteUri(GetDocumentPath(new Uri(navigationManager.BaseUri))).ToString();
    }

    public static string GetPrivateClientDocumentUrl(NavigationManager navigationManager)
    {
        return navigationManager.ToAbsoluteUri(GetPrivateClientDocumentPath(new Uri(navigationManager.BaseUri))).ToString();
    }

    public static string GetJwksDocumentUrl(NavigationManager navigationManager)
    {
        return navigationManager.ToAbsoluteUri("jwks.json").ToString();
    }

    public static string GetSigningKeyDocumentUrl(NavigationManager navigationManager)
    {
        return navigationManager.ToAbsoluteUri("signing-key.json").ToString();
    }

    public static bool ShouldDefaultClientId(string? clientId, bool? issuerSupportsCimd)
    {
        return string.IsNullOrWhiteSpace(clientId) || issuerSupportsCimd == true;
    }

    public static bool TryReadMetadataDocumentSupport(IDictionary<string, object> additionalData)
    {
        if (!additionalData.TryGetValue("client_id_metadata_document_supported", out var value))
        {
            return false;
        }

        return value switch
        {
            bool supported => supported,
            string text => bool.TryParse(text, out var parsed) && parsed,
            System.Text.Json.JsonElement element when element.ValueKind == System.Text.Json.JsonValueKind.True => true,
            System.Text.Json.JsonElement element when element.ValueKind == System.Text.Json.JsonValueKind.False => false,
            System.Text.Json.JsonElement element when element.ValueKind == System.Text.Json.JsonValueKind.String =>
                bool.TryParse(element.GetString(), out var parsed) && parsed,
            _ => false
        };
    }

    private static bool IsLocalHost(Uri baseUri)
    {
        return baseUri.IsLoopback
            || baseUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
    }
}
