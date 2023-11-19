namespace SHA1CertChecker.Shared
{
    public interface ICollisionAnalyzer
    {
        Task<bool> RunAsync(CertificateProcessingRequest request);
    }
}
