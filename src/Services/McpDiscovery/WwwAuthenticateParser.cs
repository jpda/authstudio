using System.Text.RegularExpressions;

namespace authstudio;

public record WwwAuthenticateChallenge(
    string Scheme,
    string? ResourceMetadataUrl,
    string? Scope,
    string? Error,
    string? ErrorDescription,
    string RawValue);

public static partial class WwwAuthenticateParser
{
    public static IReadOnlyList<WwwAuthenticateChallenge> Parse(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return [];
        }

        var challenges = new List<WwwAuthenticateChallenge>();
        foreach (Match match in ChallengeRegex().Matches(headerValue))
        {
            var scheme = match.Groups[1].Value;
            var parameters = match.Groups[2].Value;
            challenges.Add(BuildChallenge(scheme, parameters, match.Value.Trim()));
        }

        return challenges;
    }

    public static WwwAuthenticateChallenge? FindBearerChallenge(string? headerValue)
    {
        return Parse(headerValue)
            .FirstOrDefault(challenge => challenge.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase));
    }

    private static WwwAuthenticateChallenge BuildChallenge(string scheme, string parameters, string rawValue) =>
        new(
            scheme,
            ReadParameter(parameters, "resource_metadata"),
            ReadParameter(parameters, "scope"),
            ReadParameter(parameters, "error"),
            ReadParameter(parameters, "error_description"),
            rawValue);

    private static string? ReadParameter(string parameters, string name)
    {
        var match = ParameterRegex(name).Match(parameters);
        if (!match.Success)
        {
            return null;
        }

        return Unquote(match.Groups[1].Value);
    }

    private static string? Unquote(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && trimmed.StartsWith('"') && trimmed.EndsWith('"'))
        {
            return trimmed[1..^1];
        }

        return trimmed;
    }

    [GeneratedRegex(
        @"([A-Za-z0-9_-]+)\s+((?:[^,]|,\s*(?! [A-Za-z0-9_-]+\s))*)",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ChallengeRegex();

    private static Regex ParameterRegex(string name) =>
        new($@"{Regex.Escape(name)}\s*=\s*(""([^""\\]|\\.)*""|[^,\s]+)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
}
