namespace authstudio.Tests;

public class AuthorizeUrlSyntaxTests
{
    [Theory]
    [InlineData("client_id", AuthorizeUrlSyntax.ClientId)]
    [InlineData("redirect_uri", AuthorizeUrlSyntax.RedirectUri)]
    [InlineData("code_challenge", AuthorizeUrlSyntax.Pkce)]
    [InlineData("scope", AuthorizeUrlSyntax.OAuth)]
    [InlineData("state", AuthorizeUrlSyntax.OAuth)]
    public void GetCategory_maps_parameters(string name, string expected)
    {
        Assert.Equal(expected, AuthorizeUrlSyntax.GetCategory(name));
    }

    [Fact]
    public void OrderParameters_follows_builder_section_order()
    {
        var parameters = new[]
        {
            new KeyValuePair<string, string>("state", "abc"),
            new KeyValuePair<string, string>("client_id", "client"),
            new KeyValuePair<string, string>("scope", "openid"),
        };

        var ordered = AuthorizeUrlSyntax.OrderParameters(parameters);

        Assert.Equal(["client_id", "scope", "state"], ordered.Select(pair => pair.Key));
    }
}
