namespace authstudio;

public static class McpResourceProbe
{
    public const string InitializeRequestJson =
        """
        {
          "jsonrpc": "2.0",
          "id": 1,
          "method": "initialize",
          "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
              "name": "authstudio",
              "version": "1.0"
            }
          }
        }
        """;

    public static bool ShouldSendPostProbe(int getStatusCode) => getStatusCode != 401;
}
