using System.Security.Cryptography;
using System.Text;
namespace authstudio;
public static class Pkce
{
    // see https://dotnetfiddle.net/8jxMYZ
    public const string VERIFIER_CODE_CHARACTERS = "ABCDEFGHIJKLMNOPQURSTWXYZabcdefghijklmnopqurstwxyz0123456789-._~";

    public static string GenerateVerifier(int codeLength = 43)
    {
        byte[] randomValues = new byte[codeLength + 1];
        string randomCode = "";

        RandomNumberGenerator rng = RandomNumberGenerator.Create();

        //
        // Fill the array with random values
        rng.GetBytes(randomValues);

        //
        // Create code verification string
        foreach (byte value in randomValues)
        {
            int index = value / 4;
            randomCode += VERIFIER_CODE_CHARACTERS[index];
        }

        return randomCode;
    }

    public static string CreateChallenge(string codeVerifier)
    {
        byte[] codeVerifierSha256;
        codeVerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));

        string base64UrlEncoded = Convert.ToBase64String(codeVerifierSha256).Replace("=", "").Replace("+", "-").Replace("/",
        "_");
        return base64UrlEncoded;
    }
}