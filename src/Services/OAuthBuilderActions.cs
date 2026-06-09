namespace authstudio;

public class OAuthBuilderActions
{
    public bool IsBuilderActive { get; set; }
    public Func<Task>? AuthorizeAsync { get; set; }
}
