using SHA1CertChecker.Shared;
using System.Buffers.Text;

namespace SHA1CertChecker.Tests
{
    [TestClass]
    public class InProcessAnalyzerTests
    {
        [TestMethod]
        public void Sha1dcsum_default_initialization()
        {
            // Arrange
            NativeMethods.SHA1_CTX ctx = new NativeMethods.SHA1_CTX();

            // Act
            NativeMethods.SHA1DCInit(ref ctx);

            // Assert
            Assert.AreEqual(1, ctx.unnamed[0x60], "SafeHash not enabled by default");
        }

        [TestMethod]
        public void Sha1dcsum_safe_hash_can_be_disabled()
        {
            // Arrange
            NativeMethods.SHA1_CTX ctx = new NativeMethods.SHA1_CTX();
            NativeMethods.SHA1DCInit(ref ctx);

            // Act
            NativeMethods.SHA1DCSetSafeHash(ref ctx, 0);

            // Assert
            Assert.AreEqual(0, ctx.unnamed[0x60], "SafeHash not disabled by request");
        }

        [TestMethod]
        public void Sha1dcsum_invocation_positive_file()
        {
            // Arrange
            bool isCollision;

            // test file provided by SHAttered tool
            FileStream stream = new FileStream($".\\Data\\sha-mbles-1.bin", FileMode.Open, FileAccess.Read, FileShare.Read);
            
            // Act
            isCollision = InProcessAnalyzer.Analyze(stream);            
            
            // Assert
            Assert.AreEqual(true, isCollision);            
        }

        [TestMethod]
        public void Sha1dcsum_invocation_negative_file()
        {
            // Arrange
            bool isCollision;
            Stream stream = File.OpenRead($".\\Data\\a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc.der");

            // Act
            isCollision = InProcessAnalyzer.Analyze(stream);
                       
            // Assert
            Assert.AreEqual(false, isCollision);
        }

        [TestMethod]
        public async Task InProcessAnalyzer_RunAsync_reports_a_file_with_hash_collision()
        {
            // Arrange
            string sha256 = "Expected Sha256";
            string base64 = Convert.ToBase64String(File.ReadAllBytes($".\\Data\\sha-mbles-1.bin"));
            CertificateProcessingRequest request = new CertificateProcessingRequest
            {
                Sha256Hash = sha256,
                CertificateBase64Encoded = base64
            };

            // Act
            var result = await new InProcessAnalyzer().RunAsync(request);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task InProcessAnalyzer_RunAsync_reports_a_negative_file()
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
            var result = await new InProcessAnalyzer().RunAsync(request);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task InProcessAnalyzer_RunAsync_throws_on_corrupt_base64_data()
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
                var result = await new InProcessAnalyzer().RunAsync(request);

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