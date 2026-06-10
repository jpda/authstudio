using System.Net.Http.Headers;
using System.Text;

namespace authstudio;

public static class OAuthClientAuthentication
{
    public static void Apply(
        HttpRequestMessage request,
        ClientAppModel client,
        List<KeyValuePair<string, string>> formFields,
        string? clientAssertion = null)
    {
        switch (client.TokenAuthMethod)
        {
            case TokenClientAuthMethod.ClientSecretPost when !string.IsNullOrEmpty(client.ClientSecret):
                formFields.Add(new KeyValuePair<string, string>("client_secret", client.ClientSecret));
                request.Content = new FormUrlEncodedContent(formFields);
                break;
            case TokenClientAuthMethod.ClientSecretBasic when !string.IsNullOrEmpty(client.ClientSecret):
                var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{client.ClientId}:{client.ClientSecret}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                break;
            case TokenClientAuthMethod.PrivateKeyJwt when !string.IsNullOrEmpty(clientAssertion):
                formFields.Add(new KeyValuePair<string, string>(
                    "client_assertion_type",
                    PrivateKeyJwtGenerator.ClientAssertionType));
                formFields.Add(new KeyValuePair<string, string>("client_assertion", clientAssertion));
                request.Content = new FormUrlEncodedContent(formFields);
                break;
        }
    }
}
