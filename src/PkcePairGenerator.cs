using System.Security.Cryptography;
using System.Text;

namespace authstudio;

public static class PkcePairGenerator
{
    public const string VerifierCodeCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    public static string GenerateVerifier(int codeLength = 43)
    {
        codeLength = Math.Clamp(codeLength, 43, 128);
        var randomValues = new byte[codeLength];
        RandomNumberGenerator.Fill(randomValues);

        var builder = new StringBuilder(codeLength);
        foreach (byte value in randomValues)
        {
            builder.Append(VerifierCodeCharacters[value % VerifierCodeCharacters.Length]);
        }

        return builder.ToString();
    }

    public static string CreateChallenge(string codeVerifier)
    {
        var codeVerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        return Convert.ToBase64String(codeVerifierSha256).Replace("=", "").Replace("+", "-").Replace("/", "_");
    }
}
