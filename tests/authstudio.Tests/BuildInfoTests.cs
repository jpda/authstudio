namespace authstudio.Tests;

public class BuildInfoTests
{
    [Fact]
    public void CommitSha_is_full_revision()
    {
        Assert.NotEqual("dev", BuildInfo.CommitSha);
        Assert.Equal(40, BuildInfo.CommitSha.Length);
    }

    [Fact]
    public void RepositoryUrl_points_at_github()
    {
        Assert.StartsWith("https://github.com/", BuildInfo.RepositoryUrl);
    }

    [Fact]
    public void CommitUrl_links_repo_and_commit()
    {
        Assert.Equal(
            $"{BuildInfo.RepositoryUrl.TrimEnd('/')}/commit/{BuildInfo.CommitSha}",
            BuildInfo.CommitUrl);
    }
}
