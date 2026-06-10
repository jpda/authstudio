using System.Text;

namespace authstudio;

public record WwwAuthenticateChallenge(
    string Scheme,
    string? ResourceMetadataUrl,
    string? Scope,
    string? Error,
    string? ErrorDescription,
    string RawValue);

public static class WwwAuthenticateParser
{
    public static IReadOnlyList<WwwAuthenticateChallenge> Parse(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return [];
        }

        var challenges = new List<WwwAuthenticateChallenge>();
        foreach (var segment in SplitChallenges(headerValue))
        {
            var schemeEnd = segment.AsSpan().IndexOf(' ');
            if (schemeEnd <= 0)
            {
                continue;
            }

            var scheme = segment[..schemeEnd].Trim();
            var parameters = segment[(schemeEnd + 1)..].Trim();
            challenges.Add(BuildChallenge(scheme, parameters, segment.Trim()));
        }

        return challenges;
    }

    public static WwwAuthenticateChallenge? FindBearerChallenge(string? headerValue)
    {
        return Parse(headerValue)
            .FirstOrDefault(challenge => challenge.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase));
    }

    private static WwwAuthenticateChallenge BuildChallenge(string scheme, string parameters, string rawValue)
    {
        var parsed = ParseAuthParameters(parameters);
        parsed.TryGetValue("resource_metadata", out var resourceMetadata);
        parsed.TryGetValue("scope", out var scope);
        parsed.TryGetValue("error", out var error);
        parsed.TryGetValue("error_description", out var errorDescription);

        return new WwwAuthenticateChallenge(
            scheme,
            resourceMetadata,
            scope,
            error,
            errorDescription,
            rawValue);
    }

    internal static Dictionary<string, string> ParseAuthParameters(string parameters)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var index = 0;

        while (index < parameters.Length)
        {
            index = SkipSeparators(parameters, index);
            if (index >= parameters.Length)
            {
                break;
            }

            var nameStart = index;
            while (index < parameters.Length && parameters[index] != '=')
            {
                index++;
            }

            if (index >= parameters.Length)
            {
                break;
            }

            var name = parameters[nameStart..index].Trim();
            index++;

            index = SkipSeparators(parameters, index);
            if (index >= parameters.Length)
            {
                break;
            }

            string value;
            if (parameters[index] == '"')
            {
                index++;
                var builder = new StringBuilder();
                while (index < parameters.Length)
                {
                    if (parameters[index] == '\\' && index + 1 < parameters.Length)
                    {
                        builder.Append(parameters[index + 1]);
                        index += 2;
                        continue;
                    }

                    if (parameters[index] == '"')
                    {
                        index++;
                        break;
                    }

                    builder.Append(parameters[index]);
                    index++;
                }

                value = builder.ToString();
            }
            else
            {
                var valueStart = index;
                while (index < parameters.Length && parameters[index] != ',')
                {
                    index++;
                }

                value = parameters[valueStart..index].Trim();
            }

            if (!string.IsNullOrEmpty(name))
            {
                result[name] = value;
            }
        }

        return result;
    }

    private static IEnumerable<string> SplitChallenges(string headerValue)
    {
        var index = 0;
        while (index < headerValue.Length)
        {
            index = SkipSeparators(headerValue, index);
            if (index >= headerValue.Length)
            {
                yield break;
            }

            var start = index;
            while (index < headerValue.Length)
            {
                if (headerValue[index] == '"')
                {
                    index = SkipQuotedString(headerValue, index + 1) + 1;
                    continue;
                }

                if (headerValue[index] == ','
                    && TryReadChallengeBoundary(headerValue, index + 1, out var boundaryLength))
                {
                    yield return headerValue[start..index];
                    index += 1 + boundaryLength;
                    start = index;
                    continue;
                }

                index++;
            }

            if (start < headerValue.Length)
            {
                yield return headerValue[start..];
            }

            yield break;
        }
    }

    private static bool TryReadChallengeBoundary(string value, int index, out int boundaryLength)
    {
        boundaryLength = 0;
        var cursor = SkipSeparators(value, index);
        if (cursor >= value.Length)
        {
            return false;
        }

        var schemeStart = cursor;
        while (cursor < value.Length && value[cursor] != ' ')
        {
            cursor++;
        }

        if (cursor >= value.Length)
        {
            return false;
        }

        var scheme = value[schemeStart..cursor];
        if (!scheme.All(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_'))
        {
            return false;
        }

        boundaryLength = cursor - index;
        return true;
    }

    private static int SkipQuotedString(string value, int index)
    {
        while (index < value.Length)
        {
            if (value[index] == '\\' && index + 1 < value.Length)
            {
                index += 2;
                continue;
            }

            if (value[index] == '"')
            {
                return index;
            }

            index++;
        }

        return value.Length;
    }

    private static int SkipSeparators(string value, int index)
    {
        while (index < value.Length && (char.IsWhiteSpace(value[index]) || value[index] == ','))
        {
            index++;
        }

        return index;
    }
}
