namespace SHA1CertChecker.Shared
{
    public class HttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient()
        {
            return new HttpClient();
        }
    }
}