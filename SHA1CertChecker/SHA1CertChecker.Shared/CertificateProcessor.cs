using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SHA1CertChecker.Shared
{
    public class CertificateProcessor
    {
        public Action<int, string>? FileProcessedStatusCallback;

        public static X509Certificate2 GetCertificate(string certificateBase64)
        {
            byte[] der = Convert.FromBase64String(certificateBase64);

            return new X509Certificate2(der);
        }

        public static IEnumerable<CertificateProcessingRequest> GetRequests(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using (var reader = new StreamReader(stream))
            {
                while (!reader.EndOfStream)
                {
                    // line break delimited json format
                    CertificateProcessingRequest request = CertificateProcessingRequest.Deserialize(reader.ReadLine());

                    yield return request;
                }
            }
        }

        public async Task<ProcessedFileSummary> ProcessFile(ICollisionAnalyzer analyzer, string filePath, CancellationToken token)
        {
            ProcessedFileSummary summary = new ProcessedFileSummary(filePath);
            try
            {
                using (var stream = new FileStream(filePath, FileMode.Open))
                {
                    using (var zip = new GZipStream(stream, CompressionMode.Decompress))
                    {
                        using (StreamReader reader = new StreamReader(zip, Encoding.UTF8))
                        {
                            foreach (var request in GetRequests(zip))
                            {
                                if (token.IsCancellationRequested)
                                {
                                    break;
                                }

                                if (await analyzer.RunAsync(request))
                                {
                                    Console.WriteLine($"[!] Found a collision for cert with hash {request.Sha256Hash}");
                                    summary.Collisions.Add(request);
                                }

                                summary.CertificatesAnalyzed++;

                                if (FileProcessedStatusCallback != null)
                                {
                                    FileProcessedStatusCallback(summary.CertificatesAnalyzed, request.Sha256Hash);
                                }

                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ERROR: {ex.Message}");
                summary.Exceptions.Add(ex);
            }

            return summary;
        }
    }
}
