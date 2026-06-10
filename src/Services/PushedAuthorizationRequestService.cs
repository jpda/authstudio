namespace authstudio;

public class PushedAuthorizationRequestService(
    IHttpClientFactory clientFactory,
    ClientAssertionService clientAssertionService)
{
    public async Task<ParPushResult> PushAsync(AuthorizeRequestModel request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Issuer.PushedAuthorizationRequestEndpoint))
        {
            return new ParPushResult
            {
                IsSuccess = false,
                Error = "par_not_supported",
                ErrorDescription = "This issuer does not advertise pushed_authorization_request_endpoint."
            };
        }

        string? clientAssertion = null;
        if (request.ClientApp.TokenAuthMethod == TokenClientAuthMethod.PrivateKeyJwt)
        {
            if (string.IsNullOrWhiteSpace(request.ClientApp.SigningPrivateKeyJwk))
            {
                return new ParPushResult
                {
                    IsSuccess = false,
                    Error = "missing_signing_key",
                    ErrorDescription = "private_key_jwt requires a private JWK for PAR."
                };
            }

            clientAssertion = await clientAssertionService.CreateAssertionAsync(
                request.ClientApp.ClientId,
                request.Issuer.PushedAuthorizationRequestEndpoint,
                request.ClientApp.SigningPrivateKeyJwk,
                request.ClientApp.SigningAlgorithm);
        }

        var client = clientFactory.CreateClient("AuthClient");
        using var httpRequest = OAuthAuthorizationClient.BuildParRequest(
            request.Issuer.PushedAuthorizationRequestEndpoint,
            request,
            clientAssertion);

        using var response = await client.SendAsync(httpRequest, cancellationToken);
        var rawBody = await response.Content.ReadAsStringAsync(cancellationToken);
        return OAuthAuthorizationClient.ParseParResponse(response, rawBody);
    }
}
