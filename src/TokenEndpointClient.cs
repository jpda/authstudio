using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace authstudio;

public static class TokenEndpointClient
{
    public static HttpRequestMessage BuildTokenRequest(
        string tokenEndpoint,
        ClientAppModel client,
        AuthorizeParameterModel authorizeParameters,
        PkceChallengeModel pkceChallenge,
        string code,
        string? clientAssertion = null)
    {
        var data = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", client.RedirectUri),
            new("client_id", client.ClientId),
            new("scope", authorizeParameters.ScopeParameter),
            new("code_verifier", pkceChallenge.CodeVerifier)
        };

        var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(data)
        };

        ApplyClientAuthentication(request, client, data, clientAssertion);
        return request;
    }

    public static TokenRedeemResult ParseResponse(HttpResponseMessage response, string rawBody)
    {
        var result = new TokenRedeemResult
        {
            StatusCode = (int)response.StatusCode,
            RawBody = rawBody
        };

        OAuthErrorResponse? oauthError = null;
        try
        {
            oauthError = JsonSerializer.Deserialize<OAuthErrorResponse>(rawBody);
        }
        catch (JsonException)
        {
            // Non-JSON error bodies are shown as raw text.
        }

        if (!response.IsSuccessStatusCode || oauthError?.HasError == true)
        {
            result.IsSuccess = false;
            result.Error = oauthError?.Error;
            result.ErrorDescription = oauthError?.ErrorDescription;
            result.ErrorUri = oauthError?.ErrorUri;

            if (string.IsNullOrEmpty(result.Error) && !response.IsSuccessStatusCode)
            {
                result.Error = response.ReasonPhrase ?? "token_request_failed";
            }

            return result;
        }

        var tokens = JsonSerializer.Deserialize<TokenResponseModel>(rawBody);
        if (tokens is null || (string.IsNullOrEmpty(tokens.AccessToken) && string.IsNullOrEmpty(tokens.IdToken)))
        {
            result.IsSuccess = false;
            result.Error = "invalid_token_response";
            result.ErrorDescription = "The token endpoint returned a success status but no tokens.";
            return result;
        }

        result.IsSuccess = true;
        result.Tokens = tokens;
        return result;
    }

    private static void ApplyClientAuthentication(
        HttpRequestMessage request,
        ClientAppModel client,
        List<KeyValuePair<string, string>> data,
        string? clientAssertion)
    {
        switch (client.TokenAuthMethod)
        {
            case TokenClientAuthMethod.ClientSecretPost when !string.IsNullOrEmpty(client.ClientSecret):
                data.Add(new KeyValuePair<string, string>("client_secret", client.ClientSecret));
                request.Content = new FormUrlEncodedContent(data);
                break;
            case TokenClientAuthMethod.ClientSecretBasic when !string.IsNullOrEmpty(client.ClientSecret):
                var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{client.ClientId}:{client.ClientSecret}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                break;
            case TokenClientAuthMethod.PrivateKeyJwt when !string.IsNullOrEmpty(clientAssertion):
                data.Add(new KeyValuePair<string, string>("client_assertion_type", PrivateKeyJwtGenerator.ClientAssertionType));
                data.Add(new KeyValuePair<string, string>("client_assertion", clientAssertion));
                request.Content = new FormUrlEncodedContent(data);
                break;
        }
    }
}

public class TokenRedeemResult
{
    public bool IsSuccess { get; set; }
    public int StatusCode { get; set; }
    public string RawBody { get; set; } = "";
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
    public string? ErrorUri { get; set; }
    public TokenResponseModel? Tokens { get; set; }
}
