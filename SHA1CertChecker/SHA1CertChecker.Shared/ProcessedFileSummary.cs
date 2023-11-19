namespace SHA1CertChecker.Shared
{
    public class ProcessedFileSummary
    {
        public string FilePath { get; private set; }

        public List<CertificateProcessingRequest> Collisions { get; private set; }

        public List<Exception> Exceptions { get; private set; }

        public int CertificatesAnalyzed;

        public ProcessedFileSummary(string filePath)
        {
            FilePath = filePath;
            Collisions = new List<CertificateProcessingRequest>();
            Exceptions = new List<Exception>();
        }
    }
}