namespace authstudio.Tests;

public class JsonHighlighterTests
{
    [Fact]
    public void Tokenize_round_trips_original_text()
    {
        const string json = """
            {
              "client_id": "https://example.com/client.json",
              "redirect_uris": ["https://example.com/code"],
              "client_secret_expires_at": 0,
              "enabled": true,
              "extra": null
            }
            """;

        var rebuilt = string.Concat(JsonHighlighter.Tokenize(json).Select(token => token.Text));

        Assert.Equal(json, rebuilt);
    }

    [Fact]
    public void Tokenize_separates_keys_from_string_values()
    {
        var tokens = JsonHighlighter.Tokenize("""{"client_id": "https://example.com/client.json"}""");

        Assert.Contains(tokens, token => token.Kind == JsonTokenKind.Key && token.Text == "\"client_id\"");
        Assert.Contains(tokens, token =>
            token.Kind == JsonTokenKind.String && token.Text == "\"https://example.com/client.json\"");
    }

    [Fact]
    public void Tokenize_classifies_numbers_and_literals()
    {
        var kinds = JsonHighlighter.Tokenize("""{"a": -12.5e3, "b": false, "c": null}""")
            .Where(token => token.Kind is JsonTokenKind.Number or JsonTokenKind.Literal)
            .Select(token => token.Text)
            .ToList();

        Assert.Equal(["-12.5e3", "false", "null"], kinds);
    }

    [Fact]
    public void Tokenize_handles_escaped_quotes_inside_strings()
    {
        var tokens = JsonHighlighter.Tokenize("""{"name": "a \" b"}""");

        Assert.Contains(tokens, token => token.Kind == JsonTokenKind.String && token.Text == "\"a \\\" b\"");
    }

    [Fact]
    public void Tokenize_does_not_throw_on_malformed_json()
    {
        const string malformed = """{ "client_id": "https://example.com/client.json", """;

        var rebuilt = string.Concat(JsonHighlighter.Tokenize(malformed).Select(token => token.Text));

        Assert.Equal(malformed, rebuilt);
    }

    [Fact]
    public void Tokenize_handles_unterminated_string()
    {
        const string malformed = """{"client_id": "https://example.com""";

        var rebuilt = string.Concat(JsonHighlighter.Tokenize(malformed).Select(token => token.Text));

        Assert.Equal(malformed, rebuilt);
    }
}
