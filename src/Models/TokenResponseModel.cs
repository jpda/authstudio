
using System.Text.Json.Serialization;
namespace authstudio;

public class TokenResponseModel
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = "";
    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = "";
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; } = 0;
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = "";
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = "";
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "";

    public DateTimeOffset ExpiresAt { get { return DateTimeOffset.UtcNow.AddSeconds(ExpiresIn); } set { } }

}