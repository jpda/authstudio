using System.Text.Json.Serialization;

namespace authstudio;

public enum TokenClientAuthMethod
{
    None,
    ClientSecretPost,
    ClientSecretBasic,
    PrivateKeyJwt
}

public class OAuthErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = "";

    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; } = "";

    [JsonPropertyName("error_uri")]
    public string ErrorUri { get; set; } = "";

    public bool HasError => !string.IsNullOrEmpty(Error);
}
