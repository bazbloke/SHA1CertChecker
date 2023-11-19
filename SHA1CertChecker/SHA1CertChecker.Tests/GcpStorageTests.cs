using SHA1CertChecker.Shared;

namespace SHA1CertChecker.Tests
{
    [TestClass]
    public partial class GcpStorageTests
    {
        [TestMethod]
        public void Gcp_enumerates_bucket_contents()
        {
            // Arrange
            GcpStorage storage = new GcpStorage(null);

            // Act
            var files = storage.EnumerateFiles("test/sha");

            // Assert
            Assert.IsTrue(files.Count() > 0);
        }

        [TestMethod]
        public async Task Gcp_downloads_a_file()
        {
            // Arrange
            GcpStorage storage = new GcpStorage(null);
            string file = storage.EnumerateFiles("test/sha").ToArray()[0];
            
            using (var stream = new MemoryStream())
            {
                // Act
                await storage.DownloadFileAsync(file, stream);

                // Assert
                stream.Position = 0;
                Assert.AreEqual(770, stream.ToArray().Length);
            }
        }
    }
}