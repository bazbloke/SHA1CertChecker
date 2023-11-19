using SHA1CertChecker.Shared;

namespace SHA1CertChecker.Tests
{
    [TestClass]
    public class IsolatedAnalyzerTests
    {
        [TestMethod]
        public async Task IsolatedAnalyzer_EvaluateCollisionAsync_reports_a_file_with_hash_collision()
        {
            // Arrange            
            byte[] content = File.ReadAllBytes($".\\Data\\sha-mbles-1.bin");

            // Act
            var result = await new IsolatedAnalyzer().EvaluateCollisionAsync(content);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task IsolatedAnalyzer_EvaluateCollisionAsync_reports_a_file_with_no_collision()
        {
            // Arrange            
            byte[] content = File.ReadAllBytes($".\\Data\\a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc.der");

            // Act
            var result = await new IsolatedAnalyzer().EvaluateCollisionAsync(content);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task IsolatedAnalyzer_RunAsync_reports_a_negative_file()
        {
            // Arrange            
            string sha256 = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc";
            string base64 = File.ReadAllText($".\\Data\\{sha256}.b64");
            CertificateProcessingRequest request = new CertificateProcessingRequest
            {
                Sha256Hash = sha256,
                CertificateBase64Encoded = base64
            };

            // Act
            var result = await new IsolatedAnalyzer().RunAsync(request);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task IsolatedAnalyzer_RunAsync_throws_on_corrupt_base64_data()
        {
            // Arrange
            string sha256 = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc";
            string base64 = "asjkdhasd89sadh2[";
            CertificateProcessingRequest request = new CertificateProcessingRequest
            {
                Sha256Hash = sha256,
                CertificateBase64Encoded = base64
            };

            // Act
            try
            {
                var result = await new IsolatedAnalyzer().RunAsync(request);

                Assert.Fail("Did not throw FormatException");
            }
            catch (FormatException ex)
            {
                // Assert
                Assert.IsTrue(ex.Message.StartsWith("The input is not a valid Base-64 string"));
            }
        }
    }
}