using System.Text.Json;
using System.Text.Json.Nodes;

namespace authstudio;

public class CimdDocumentModel
{
    public string ClientId { get; set; } = "";
    public string ClientName { get; set; } = "";
    public string ClientUri { get; set; } = "";
    public List<string> RedirectUris { get; set; } = [];
    public List<string> GrantTypes { get; set; } = ["authorization_code"];
    public List<string> ResponseTypes { get; set; } = ["code"];
    public string TokenEndpointAuthMethod { get; set; } = "none";
    public string TokenEndpointAuthSigningAlg { get; set; } = "";
    public string JwksUri { get; set; } = "";
    public string Scope { get; set; } = "";
    public string TosUri { get; set; } = "";
    public string PolicyUri { get; set; } = "";
    public string LogoUri { get; set; } = "";

    public string RedirectUrisText
    {
        get => string.Join('\n', RedirectUris);
        set => RedirectUris = SplitLines(value);
    }

    public string GrantTypesText
    {
        get => string.Join(' ', GrantTypes);
        set => GrantTypes = SplitTokens(value);
    }

    public string ResponseTypesText
    {
        get => string.Join(' ', ResponseTypes);
        set => ResponseTypes = SplitTokens(value);
    }

    private static List<string> SplitLines(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();

    private static List<string> SplitTokens(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split([' ', ',', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
}

public static class CimdDocument
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static string ToJson(CimdDocumentModel model)
    {
        var obj = new JsonObject();
        AddString(obj, "client_id", model.ClientId);
        AddString(obj, "client_name", model.ClientName);
        AddString(obj, "client_uri", model.ClientUri);
        AddStringArray(obj, "redirect_uris", model.RedirectUris);
        AddStringArray(obj, "grant_types", model.GrantTypes);
        AddStringArray(obj, "response_types", model.ResponseTypes);
        AddString(obj, "token_endpoint_auth_method", model.TokenEndpointAuthMethod);
        AddString(obj, "token_endpoint_auth_signing_alg", model.TokenEndpointAuthSigningAlg);
        AddString(obj, "jwks_uri", model.JwksUri);
        AddString(obj, "scope", model.Scope);
        AddString(obj, "tos_uri", model.TosUri);
        AddString(obj, "policy_uri", model.PolicyUri);
        AddString(obj, "logo_uri", model.LogoUri);
        return obj.ToJsonString(JsonOptions);
    }

    public static CimdDocumentModel Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        return new CimdDocumentModel
        {
            ClientId = ReadString(root, "client_id"),
            ClientName = ReadString(root, "client_name"),
            ClientUri = ReadString(root, "client_uri"),
            RedirectUris = ReadStringArray(root, "redirect_uris"),
            GrantTypes = ReadStringArray(root, "grant_types"),
            ResponseTypes = ReadStringArray(root, "response_types"),
            TokenEndpointAuthMethod = ReadString(root, "token_endpoint_auth_method"),
            TokenEndpointAuthSigningAlg = ReadString(root, "token_endpoint_auth_signing_alg"),
            JwksUri = ReadString(root, "jwks_uri"),
            Scope = ReadString(root, "scope"),
            TosUri = ReadString(root, "tos_uri"),
            PolicyUri = ReadString(root, "policy_uri"),
            LogoUri = ReadString(root, "logo_uri")
        };
    }

    public static CimdDocumentModel FromWorkspace(
        ClientAppModel client,
        AuthorizeParameterModel? authorize,
        string jwksUri)
    {
        var model = new CimdDocumentModel
        {
            ClientId = client.ClientId,
            RedirectUris = string.IsNullOrWhiteSpace(client.RedirectUri) ? [] : [client.RedirectUri],
            GrantTypes = ["authorization_code"],
            ResponseTypes = SplitResponseTypes(authorize?.ResponseType),
            TokenEndpointAuthMethod = ToAuthMethodValue(client.TokenAuthMethod)
        };

        if (client.TokenAuthMethod == TokenClientAuthMethod.PrivateKeyJwt)
        {
            model.TokenEndpointAuthSigningAlg = client.SigningAlgorithm;
            model.JwksUri = jwksUri;
        }

        return model;
    }

    public static void OverlayWorkspace(CimdDocumentModel model, CimdDocumentModel workspace)
    {
        model.ClientId = workspace.ClientId;
        model.RedirectUris = workspace.RedirectUris;
        model.GrantTypes = workspace.GrantTypes.Count > 0 ? workspace.GrantTypes : model.GrantTypes;
        model.ResponseTypes = workspace.ResponseTypes.Count > 0 ? workspace.ResponseTypes : model.ResponseTypes;
        model.TokenEndpointAuthMethod = workspace.TokenEndpointAuthMethod;
        model.TokenEndpointAuthSigningAlg = workspace.TokenEndpointAuthSigningAlg;
        model.JwksUri = workspace.JwksUri;
        if (!string.IsNullOrWhiteSpace(workspace.Scope))
        {
            model.Scope = workspace.Scope;
        }
    }

    public static string ToAuthMethodValue(TokenClientAuthMethod method) => method switch
    {
        TokenClientAuthMethod.ClientSecretPost => "client_secret_post",
        TokenClientAuthMethod.ClientSecretBasic => "client_secret_basic",
        TokenClientAuthMethod.PrivateKeyJwt => "private_key_jwt",
        _ => "none"
    };

    private static List<string> SplitResponseTypes(string? responseType) =>
        string.IsNullOrWhiteSpace(responseType)
            ? ["code"]
            : responseType.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static void AddString(JsonObject obj, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            obj[name] = value.Trim();
        }
    }

    private static void AddStringArray(JsonObject obj, string name, IReadOnlyList<string> values)
    {
        var items = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .ToList();
        if (items.Count == 0)
        {
            return;
        }

        var array = new JsonArray();
        foreach (var item in items)
        {
            array.Add(item);
        }

        obj[name] = array;
    }

    private static string ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : "";

    private static List<string> ReadStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return value.EnumerateArray()
            .Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item!)
            .ToList();
    }
}
