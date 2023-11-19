namespace SHA1CertChecker.Shared
{
    public interface ICensysClient
    {
        Task<string> GetCertificateJson(string sha256);
    }
}