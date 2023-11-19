using System.Text;

namespace SHA1CertChecker.Shared
{
    public class CensysClient : ICensysClient
    {
        private const string CENSYS_PEM_ENDPOINT = "https://search.censys.io/api/v2/certificates/{0}";
        private const int MAX_RETRY_ATTEMPTS = 3;

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly string _token;

        public CensysClient(IHttpClientFactory httpClientFactory, string appId, string secret)
        {
            if (httpClientFactory == null)
            {
                throw new ArgumentNullException(nameof(httpClientFactory));
            }

            if (string.IsNullOrEmpty(appId))
            {
                throw new ArgumentNullException(nameof(appId));
            }

            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentNullException(nameof(secret));
            }

            this._httpClientFactory = httpClientFactory;
            this._token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{appId}:{secret}"));
        }

        public CensysClient(string appId, string secret) : this(new HttpClientFactory(), appId, secret)
        {
        }

        public async Task<string> GetCertificateJson(string sha256)
        {
            HttpClient client = _httpClientFactory.CreateClient();

            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76");
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.DefaultRequestHeaders.Add("Authorization", $"Basic {_token}");

            string uri = string.Format(CENSYS_PEM_ENDPOINT, sha256);

            int attempts = 1;

            while (true)
            {
                try
                {
                    return await client.GetStringAsync(uri);
                }
                catch (HttpRequestException ex)
                {
                    if (ex.StatusCode != System.Net.HttpStatusCode.TooManyRequests || attempts >= MAX_RETRY_ATTEMPTS)
                    {
                        throw;
                    }
                    else
                    {
                        await Task.Delay(attempts * 500);
                        attempts++;
                    }
                }
            }
        }
    }
}
