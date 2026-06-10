using System.Reflection;

namespace authstudio;

public static class BuildInfo
{
    private static readonly Assembly AppAssembly = typeof(BuildInfo).Assembly;

    public static string RepositoryUrl =>
        GetMetadata("RepositoryUrl") ?? "https://github.com/jpda/authstudio";

    public static string CommitSha =>
        GetMetadata("SourceRevisionId")
        ?? ParseCommitFromInformationalVersion()
        ?? "dev";

    public static string CommitUrl =>
        $"{RepositoryUrl.TrimEnd('/')}/commit/{CommitSha}";

    private static string? GetMetadata(string key) =>
        AppAssembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => attribute.Key == key)?.Value;

    private static string? ParseCommitFromInformationalVersion()
    {
        var informationalVersion = AppAssembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrEmpty(informationalVersion))
        {
            return null;
        }

        var separator = informationalVersion.IndexOf('+');
        return separator >= 0 ? informationalVersion[(separator + 1)..] : null;
    }
}
