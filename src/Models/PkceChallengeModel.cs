using System.ComponentModel.DataAnnotations;
namespace authstudio;
public class PkceChallengeModel
{
    [Range(43, 128)]
    public int Length { get; set; } = 43;
    public string CodeVerifier { get; set; } = "";
    public string CodeChallenge { get; set; } = "";
    public string CodeChallengeMethod { get; set; } = "S256";

    public string GenerateAuthorizeUrlFragment()
    {
        return $"code_challenge={CodeChallenge}&code_challenge_method={CodeChallengeMethod}";
    }
}