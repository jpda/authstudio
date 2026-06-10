using System.Net.Http.Headers;
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

        if (!string.IsNullOrWhiteSpace(authorizeParameters.Resource))
        {
            data.Add(new KeyValuePair<string, string>("resource", authorizeParameters.Resource));
        }

        var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(data)
        };

        OAuthClientAuthentication.Apply(request, client, data, clientAssertion);
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
