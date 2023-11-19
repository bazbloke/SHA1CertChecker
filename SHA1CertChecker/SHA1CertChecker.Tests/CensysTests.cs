using Microsoft.Extensions.Configuration;
using Moq;
using Newtonsoft.Json;
using SHA1CertChecker.Shared;
using System.Diagnostics;
using System.Net;
using System.Web.Http;

namespace SHA1CertChecker.Tests
{
    [TestClass]
    public partial class CensysTests
    {
        private string? _censysAppid;
        private string? _censysSecret;

        [TestInitialize]
        public void Initialize()
        {
            var builder = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .AddUserSecrets<CensysTests>();
            IConfiguration configuration = builder.Build();

            this._censysAppid = configuration[Constants.CENSYS_APPID_KEY];
            this._censysSecret = configuration[Constants.CENSYS_SECRET_KEY];
        }

        [TestMethod]
        public async Task Censys_successfully_returns_a_request()
        {
            // Arrange
            string sha256 = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc";

            string raw = File.ReadAllText($".\\Data\\{sha256}.b64");

            CensysClient client = new CensysClient(this._censysAppid, this._censysSecret);

            // Act
            var result = await client.GetCertificateJson(sha256);

            dynamic j = JsonConvert.DeserializeObject(result);

            // Assert
            Assert.AreEqual(200, j.code.Value);
            Assert.AreEqual(raw, j.result.raw.Value);
        }

        [TestMethod]
        public async Task Censys_returns_422_for_an_invalid_hash()
        {
            // Arrange
            string sha256 = "ZZZZ";

            CensysClient client = new CensysClient(this._censysAppid, this._censysSecret);

            // Act
            try
            {
                var result = await client.GetCertificateJson(sha256);
            }
            catch (HttpRequestException ex) 
            {
                // Assert
                Assert.AreEqual(ex.StatusCode, HttpStatusCode.UnprocessableEntity);
            }            
        }

        [TestMethod]
        public async Task Censys_retries_when_there_are_too_many_requests()
        {
            // Arrange
            string sha256 = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc";

            Mock<SHA1CertChecker.Shared.IHttpClientFactory> factory = new Mock<SHA1CertChecker.Shared.IHttpClientFactory>();
                        
            int attempts = 0;
            var configuration = new HttpConfiguration();
            var clientHandlerStub = new DelegatingHandlerStub((request, cancellationToken) => {
                attempts++;
                request.SetConfiguration(configuration);
                var response = request.CreateResponse(HttpStatusCode.TooManyRequests, "json");
                return Task.FromResult(response);
            });
                        
            factory
                .Setup(m => m.CreateClient())
                .Returns(new HttpClient(clientHandlerStub));

            CensysClient client = new CensysClient(factory.Object, this._censysAppid, this._censysSecret);

            Stopwatch stopwatch = Stopwatch.StartNew();

            // Act
            try
            {
                var result = await client.GetCertificateJson(sha256);
            }
            catch (HttpRequestException ex)
            {
                stopwatch.Stop();

                // Assert
                Assert.AreEqual(ex.StatusCode, HttpStatusCode.TooManyRequests);

                // retried operation 3 times
                Assert.AreEqual(3, attempts);

                // waited at least 500 + 1000 ms
                Assert.IsTrue(stopwatch.ElapsedMilliseconds > 1500);
            }
        }
    }
}