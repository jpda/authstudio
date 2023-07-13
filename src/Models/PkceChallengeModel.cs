using System.ComponentModel.DataAnnotations;
namespace authstudio;

public enum ChallengeMethod { Plain, S256 };

public class PkceChallengeModel
{
    [Range(43, 128)]
    public int Length { get; set; } = 43;
    public string CodeVerifier { get; set; } = "";
    public string CodeChallenge { get; set; } = "";
    public ChallengeMethod CodeChallengeMethod { get; set; } = ChallengeMethod.S256;

    public string GenerateAuthorizeUrlFragment()
    {
        return $"code_challenge={CodeChallenge}&code_challenge_method={CodeChallengeMethod}";
    }

    public void GenerateChallenge()
    {
        CodeVerifier = PkcePairGenerator.GenerateVerifier(Length);
        CodeChallenge = PkcePairGenerator.CreateChallenge(CodeVerifier);
    }
}