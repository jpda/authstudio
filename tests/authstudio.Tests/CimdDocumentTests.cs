using System.Text.Json;

namespace authstudio.Tests;

public class CimdDocumentTests
{
    [Fact]
    public void ToJson_includes_core_fields_and_omits_empty_optionals()
    {
        var json = CimdDocument.ToJson(new CimdDocumentModel
        {
            ClientId = "https://example.com/client.json",
            ClientName = "Example",
            RedirectUris = ["https://example.com/code"],
            GrantTypes = ["authorization_code"],
            ResponseTypes = ["code"],
            TokenEndpointAuthMethod = "none"
        });

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal("https://example.com/client.json", root.GetProperty("client_id").GetString());
        Assert.Equal(["https://example.com/code"], ReadStrings(root, "redirect_uris"));
        Assert.Equal("none", root.GetProperty("token_endpoint_auth_method").GetString());
        Assert.False(root.TryGetProperty("jwks_uri", out _));
        Assert.False(root.TryGetProperty("scope", out _));
    }

    [Fact]
    public void FromWorkspace_maps_private_key_jwt()
    {
        var model = CimdDocument.FromWorkspace(
            new ClientAppModel
            {
                ClientId = "https://example.com/private-client.json",
                RedirectUri = "https://example.com/code",
                TokenAuthMethod = TokenClientAuthMethod.PrivateKeyJwt,
                SigningAlgorithm = "ES256"
            },
            new AuthorizeParameterModel { ResponseType = "code" },
            "https://example.com/jwks.json");

        Assert.Equal("private_key_jwt", model.TokenEndpointAuthMethod);
        Assert.Equal("ES256", model.TokenEndpointAuthSigningAlg);
        Assert.Equal("https://example.com/jwks.json", model.JwksUri);
        Assert.Contains("jwks_uri", CimdDocument.ToJson(model));
    }

    [Fact]
    public void Parse_round_trips_document()
    {
        var original = new CimdDocumentModel
        {
            ClientId = "https://example.com/client.json",
            ClientName = "Example",
            ClientUri = "https://example.com",
            RedirectUris = ["https://example.com/code"],
            GrantTypes = ["authorization_code"],
            ResponseTypes = ["code"],
            TokenEndpointAuthMethod = "private_key_jwt",
            TokenEndpointAuthSigningAlg = "ES256",
            JwksUri = "https://example.com/jwks.json",
            Scope = "openid profile"
        };

        var parsed = CimdDocument.Parse(CimdDocument.ToJson(original));

        Assert.Equal(original.ClientId, parsed.ClientId);
        Assert.Equal(original.RedirectUris, parsed.RedirectUris);
        Assert.Equal(original.TokenEndpointAuthMethod, parsed.TokenEndpointAuthMethod);
        Assert.Equal(original.JwksUri, parsed.JwksUri);
        Assert.Equal(original.Scope, parsed.Scope);
    }

    [Fact]
    public void OverlayWorkspace_keeps_descriptive_metadata()
    {
        var model = new CimdDocumentModel
        {
            ClientName = "Hosted",
            LogoUri = "https://example.com/logo.png",
            TokenEndpointAuthMethod = "none"
        };

        CimdDocument.OverlayWorkspace(
            model,
            new CimdDocumentModel
            {
                ClientId = "https://example.com/client.json",
                RedirectUris = ["https://example.com/code"],
                TokenEndpointAuthMethod = "none"
            });

        Assert.Equal("https://example.com/client.json", model.ClientId);
        Assert.Equal("Hosted", model.ClientName);
        Assert.Equal("https://example.com/logo.png", model.LogoUri);
    }

    private static List<string> ReadStrings(JsonElement root, string name) =>
        root.GetProperty(name).EnumerateArray().Select(item => item.GetString() ?? "").ToList();
}
