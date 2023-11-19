namespace SHA1CertChecker.Shared
{
    /// <summary>
    /// Performs SHA-1 collision analysis by invoking the sha1dcsum library directly.
    /// </summary>
    public class InProcessAnalyzer : ICollisionAnalyzer
    {
        public async Task<bool> RunAsync(CertificateProcessingRequest request)
        {
            if (!string.IsNullOrEmpty(request.Sha256Hash) &&
                !string.IsNullOrEmpty(request.CertificateBase64Encoded))
            {
                byte[] der = Convert.FromBase64String(request.CertificateBase64Encoded);

                using (MemoryStream stream = new MemoryStream(der))
                {
                    return Analyze(stream);
                }
            }

            return false;
        }

        public static bool Analyze(Stream stream)
        {
            NativeMethods.SHA1_CTX ctx = new NativeMethods.SHA1_CTX();
            NativeMethods.SHA1DCInit(ref ctx);
            NativeMethods.SHA1DCSetSafeHash(ref ctx, 0);

            byte[] bytes = new byte[65536];

            int count = (int)stream.Length;
            int index = 0;

            while (count > 0)
            {
                int n = stream.Read(bytes, index, count);
                if (n == 0)
                {
                    break;
                }

                index += n;
                count -= n;

                NativeMethods.SHA1DCUpdate(ref ctx, bytes, n);
            }

            byte[] hash = new byte[20];
            bool isCollision = NativeMethods.SHA1DCFinal(hash, ref ctx) > 0 ? true : false;

            return isCollision;
        }
    }
}