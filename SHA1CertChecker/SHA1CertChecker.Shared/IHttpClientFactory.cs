namespace SHA1CertChecker.Shared
{
    public interface IHttpClientFactory
    {
        HttpClient CreateClient();
    }
}