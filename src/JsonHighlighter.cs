namespace authstudio;

public enum JsonTokenKind
{
    Plain,
    Key,
    String,
    Number,
    Literal,
    Punctuation
}

public record JsonToken(string Text, JsonTokenKind Kind);

public static class JsonHighlighter
{
    public static IReadOnlyList<JsonToken> Tokenize(string json)
    {
        var tokens = new List<JsonToken>();
        if (string.IsNullOrEmpty(json))
        {
            return tokens;
        }

        var index = 0;
        while (index < json.Length)
        {
            var current = json[index];

            if (current == '"')
            {
                var end = ScanString(json, index);
                var text = json[index..end];
                tokens.Add(new JsonToken(text, IsKey(json, end) ? JsonTokenKind.Key : JsonTokenKind.String));
                index = end;
                continue;
            }

            if (current is '{' or '}' or '[' or ']' or ',' or ':')
            {
                tokens.Add(new JsonToken(current.ToString(), JsonTokenKind.Punctuation));
                index++;
                continue;
            }

            if (char.IsDigit(current) || (current == '-' && index + 1 < json.Length && char.IsDigit(json[index + 1])))
            {
                var end = index + 1;
                while (end < json.Length && (char.IsDigit(json[end]) || json[end] is '.' or 'e' or 'E' or '+' or '-'))
                {
                    end++;
                }

                tokens.Add(new JsonToken(json[index..end], JsonTokenKind.Number));
                index = end;
                continue;
            }

            if (TryReadLiteral(json, index, out var literal))
            {
                tokens.Add(new JsonToken(literal, JsonTokenKind.Literal));
                index += literal.Length;
                continue;
            }

            var plainEnd = index;
            while (plainEnd < json.Length && !IsTokenStart(json, plainEnd))
            {
                plainEnd++;
            }

            if (plainEnd == index)
            {
                plainEnd++;
            }

            tokens.Add(new JsonToken(json[index..plainEnd], JsonTokenKind.Plain));
            index = plainEnd;
        }

        return tokens;
    }

    private static bool IsTokenStart(string json, int index)
    {
        var current = json[index];
        return current is '"' or '{' or '}' or '[' or ']' or ',' or ':'
            || char.IsDigit(current)
            || (current == '-' && index + 1 < json.Length && char.IsDigit(json[index + 1]))
            || TryReadLiteral(json, index, out _);
    }

    private static int ScanString(string json, int start)
    {
        var index = start + 1;
        while (index < json.Length)
        {
            if (json[index] == '\\')
            {
                index += 2;
                continue;
            }

            if (json[index] == '"')
            {
                return index + 1;
            }

            index++;
        }

        return json.Length;
    }

    private static bool IsKey(string json, int afterString)
    {
        for (var index = afterString; index < json.Length; index++)
        {
            if (char.IsWhiteSpace(json[index]))
            {
                continue;
            }

            return json[index] == ':';
        }

        return false;
    }

    private static bool TryReadLiteral(string json, int index, out string literal)
    {
        foreach (var candidate in (string[])["true", "false", "null"])
        {
            if (string.CompareOrdinal(json, index, candidate, 0, candidate.Length) == 0)
            {
                literal = candidate;
                return true;
            }
        }

        literal = "";
        return false;
    }
}
