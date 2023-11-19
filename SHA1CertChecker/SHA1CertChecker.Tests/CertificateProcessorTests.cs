using SHA1CertChecker.Shared;

namespace SHA1CertChecker.Tests
{
    [TestClass]
    public class CertificateProcessorTests
    {
        [TestMethod]
        public void CertificateProcessor_GetCertificate_retrieves_and_parses_a_certificate()
        {
            // Arrange
            string sha256 = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc";

            string base64 = File.ReadAllText($".\\Data\\{sha256}.b64");

            // Act
            var result = CertificateProcessor.GetCertificate(base64);

            // Assert
            Assert.AreEqual("CN=usswan-ddjjkpcnbm.dynamic-m.com, O=Cisco Systems Inc., L=San Jose, S=California, C=US", result.SubjectName.Name);
        }

        [TestMethod]
        public void CertificateProcessor_GetRequests_returns_the_expected_values()
        {
            // Arrange

            // Act
            CertificateProcessingRequest[] requests = CertificateProcessor.GetRequests(File.OpenRead(".\\Data\\10certificates.json")).ToArray();

            // Assert
            Assert.AreEqual(10, requests.Length);

            var cert0 = CertificateProcessor.GetCertificate(requests[0].CertificateBase64Encoded);
            Assert.AreEqual("CN=formation.fastlearner.fr", cert0.SubjectName.Name);
            Assert.AreEqual("12b069dcf4bbfc5d92a5804adcad9f778ed17355048ae420e9d60fca668b0f07", requests[0].Sha256Hash);

            var cert9 = CertificateProcessor.GetCertificate(requests[9].CertificateBase64Encoded);
            Assert.AreEqual("CN=trade3.123online.nz", cert9.SubjectName.Name);
            Assert.AreEqual("1b358779bee42138dd747064404b51ec74381fe70db35a3fcaf2dd9d09bb7adc", requests[9].Sha256Hash);
        }

        [TestMethod]
        public async Task CertificateProcessor_ProcessFile_returns_the_expected_values_for_inprocess_mode()
        {
            // Arrange

            // Act
            var summary = await new CertificateProcessor().ProcessFile(new InProcessAnalyzer(), ".\\Data\\10certificates.gz", new CancellationToken());

            // Assert
            Assert.AreEqual(".\\Data\\10certificates.gz", summary.FilePath);
            Assert.AreEqual(10, summary.CertificatesAnalyzed);
            Assert.AreEqual(0, summary.Collisions.Count());
            Assert.AreEqual(0, summary.Exceptions.Count());
        }

        [TestMethod]
        public async Task CertificateProcessor_ProcessFile_returns_the_expected_values_for_isolated_mode()
        {
            // Arrange

            // Act
            var summary = await new CertificateProcessor().ProcessFile(new IsolatedAnalyzer(), ".\\Data\\10certificates.gz", new CancellationToken());

            // Assert
            Assert.AreEqual(".\\Data\\10certificates.gz", summary.FilePath);
            Assert.AreEqual(10, summary.CertificatesAnalyzed);
            Assert.AreEqual(0, summary.Collisions.Count());
            Assert.AreEqual(0, summary.Exceptions.Count());
        }

        [TestMethod]
        public async Task CertificateProcessor_ProcessFile_returns_finds_a_positive_file_inprocess_mode()
        {
            // Arrange

            // Act
            var summary = await new CertificateProcessor().ProcessFile(new InProcessAnalyzer(), ".\\Data\\sha-mbles-1.gz", new CancellationToken());

            // Assert
            Assert.AreEqual(".\\Data\\sha-mbles-1.gz", summary.FilePath);
            Assert.AreEqual(1, summary.CertificatesAnalyzed);
            Assert.AreEqual(1, summary.Collisions.Count());
            Assert.AreEqual("457870656374656420536861323536", summary.Collisions[0].Sha256Hash);
            Assert.AreEqual(0, summary.Exceptions.Count());
        }

        [TestMethod]
        public async Task CertificateProcessor_ProcessFile_returns_finds_a_positive_file_isolated_mode()
        {
            // Arrange

            // Act
            var summary = await new CertificateProcessor().ProcessFile(new IsolatedAnalyzer(), ".\\Data\\sha-mbles-1.gz", new CancellationToken());

            // Assert
            Assert.AreEqual(".\\Data\\sha-mbles-1.gz", summary.FilePath);
            Assert.AreEqual(1, summary.CertificatesAnalyzed);
            Assert.AreEqual(1, summary.Collisions.Count());
            Assert.AreEqual("457870656374656420536861323536", summary.Collisions[0].Sha256Hash);
            Assert.AreEqual(0, summary.Exceptions.Count());
        }

        [TestMethod]
        public async Task CertificateProcessor_ProcessFile_passes_exceptions_inprocess_mode()
        {
            // Arrange

            // Act
            var summary = await new CertificateProcessor().ProcessFile(new InProcessAnalyzer(), "NOT A FILE", new CancellationToken());

            // Assert
            Assert.AreEqual("NOT A FILE", summary.FilePath);
            Assert.AreEqual(0, summary.CertificatesAnalyzed);
            Assert.AreEqual(0, summary.Collisions.Count());
            Assert.AreEqual(1, summary.Exceptions.Count());
            Assert.AreEqual("FileNotFoundException", summary.Exceptions[0].GetType().Name);
        }

        [TestMethod]
        public async Task CertificateProcessor_ProcessFile_passes_exceptions_isolated_mode()
        {
            // Arrange

            // Act
            var summary = await new CertificateProcessor().ProcessFile(new IsolatedAnalyzer(), "NOT A FILE", new CancellationToken());

            // Assert
            Assert.AreEqual("NOT A FILE", summary.FilePath);
            Assert.AreEqual(0, summary.CertificatesAnalyzed);
            Assert.AreEqual(0, summary.Collisions.Count());
            Assert.AreEqual(1, summary.Exceptions.Count());
            Assert.AreEqual("FileNotFoundException", summary.Exceptions[0].GetType().Name);
        }
    }
}