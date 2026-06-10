namespace authstudio.Tests;

public class PkcePairGeneratorTests
{
    [Fact]
    public void GenerateVerifier_respects_length_bounds()
    {
        Assert.Equal(43, PkcePairGenerator.GenerateVerifier(43).Length);
        Assert.Equal(128, PkcePairGenerator.GenerateVerifier(200).Length);
        Assert.Equal(43, PkcePairGenerator.GenerateVerifier(10).Length);
    }

    [Fact]
    public void GenerateVerifier_uses_unreserved_characters_only()
    {
        var verifier = PkcePairGenerator.GenerateVerifier();
        Assert.All(verifier, c => Assert.Contains(c, PkcePairGenerator.VerifierCodeCharacters));
    }

    [Fact]
    public void CreateChallenge_matches_rfc7636_example()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        Assert.Equal(expected, PkcePairGenerator.CreateChallenge(verifier));
    }
}
