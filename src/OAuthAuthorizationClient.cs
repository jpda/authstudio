using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace authstudio;

public static class OAuthAuthorizationClient
{
    public static Dictionary<string, string?> BuildAuthorizeParameters(AuthorizeRequestModel request)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["client_id"] = request.ClientApp.ClientId,
            ["redirect_uri"] = request.ClientApp.RedirectUri,
            ["response_type"] = request.AuthorizeParameters.ResponseType,
            ["scope"] = request.AuthorizeParameters.ScopeParameter,
            ["code_challenge"] = request.PkceChallenge.CodeChallenge,
            ["code_challenge_method"] = request.PkceChallenge.CodeChallengeMethod.ToString(),
            ["state"] = request.Id
        };

        if (ShouldIncludeResponseMode(request.AuthorizeParameters.ResponseMode))
        {
            parameters["response_mode"] = request.AuthorizeParameters.ResponseMode;
        }

        if (!string.IsNullOrWhiteSpace(request.AuthorizeParameters.Resource))
        {
            parameters["resource"] = request.AuthorizeParameters.Resource;
        }

        return parameters;
    }

    public static string BuildDirectAuthorizeUrl(AuthorizeRequestModel request)
    {
        if (string.IsNullOrEmpty(request.Issuer.AuthorizeEndpoint))
        {
            return "";
        }

        return QueryHelpers.AddQueryString(
            request.Issuer.AuthorizeEndpoint,
            BuildAuthorizeParameters(request));
    }

    public static string BuildFrontChannelAuthorizeUrl(AuthorizeRequestModel request, string requestUri)
    {
        if (string.IsNullOrEmpty(request.Issuer.AuthorizeEndpoint))
        {
            return "";
        }

        return QueryHelpers.AddQueryString(
            request.Issuer.AuthorizeEndpoint,
            new Dictionary<string, string?>
            {
                ["client_id"] = request.ClientApp.ClientId,
                ["request_uri"] = requestUri
            });
    }

    public static HttpRequestMessage BuildParRequest(
        string parEndpoint,
        AuthorizeRequestModel request,
        string? clientAssertion = null)
    {
        var formFields = BuildAuthorizeParameters(request)
            .Where(pair => !string.IsNullOrEmpty(pair.Value))
            .Select(pair => new KeyValuePair<string, string>(pair.Key, pair.Value!))
            .ToList();

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, parEndpoint)
        {
            Content = new FormUrlEncodedContent(formFields)
        };

        OAuthClientAuthentication.Apply(httpRequest, request.ClientApp, formFields, clientAssertion);
        return httpRequest;
    }

    public static ParPushResult ParseParResponse(HttpResponseMessage response, string rawBody)
    {
        var result = new ParPushResult
        {
            StatusCode = (int)response.StatusCode,
            RawBody = rawBody
        };

        if (!response.IsSuccessStatusCode)
        {
            result.IsSuccess = false;
            TryReadOAuthError(rawBody, result);
            return result;
        }

        try
        {
            using var document = JsonDocument.Parse(rawBody);
            var root = document.RootElement;
            result.RequestUri = root.TryGetProperty("request_uri", out var requestUri)
                ? requestUri.GetString() ?? ""
                : "";
            result.ExpiresIn = root.TryGetProperty("expires_in", out var expiresIn)
                ? expiresIn.GetInt32()
                : null;

            if (string.IsNullOrEmpty(result.RequestUri))
            {
                result.IsSuccess = false;
                result.Error = "invalid_par_response";
                result.ErrorDescription = "The PAR endpoint did not return request_uri.";
                return result;
            }

            result.IsSuccess = true;
            return result;
        }
        catch (JsonException ex)
        {
            result.IsSuccess = false;
            result.Error = "invalid_par_response";
            result.ErrorDescription = ex.Message;
            return result;
        }
    }

    public static bool ShouldIncludeResponseMode(string? responseMode) =>
        !string.IsNullOrWhiteSpace(responseMode)
        && !string.Equals(responseMode, "query", StringComparison.Ordinal);

    private static void TryReadOAuthError(string rawBody, ParPushResult result)
    {
        try
        {
            var oauthError = JsonSerializer.Deserialize<OAuthErrorResponse>(rawBody);
            if (oauthError?.HasError == true)
            {
                result.Error = oauthError.Error;
                result.ErrorDescription = oauthError.ErrorDescription;
                result.ErrorUri = oauthError.ErrorUri;
            }
        }
        catch (JsonException)
        {
            // Show raw body in UI.
        }

        result.Error ??= "par_request_failed";
    }
}

public class ParPushResult
{
    public bool IsSuccess { get; set; }
    public int StatusCode { get; set; }
    public string RawBody { get; set; } = "";
    public string RequestUri { get; set; } = "";
    public int? ExpiresIn { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
    public string? ErrorUri { get; set; }
}
