using CommandLine;
using SHA1CertChecker.Shared;

namespace SHA1CertChecker
{
    [Verb("add", false, new[] { "a" }, HelpText = "Add a workitem to the queue.")]
    public class PublishOptions
    {
        [Option('f', "folder",
            Required = false,
            Default = Constants.GCP_DATA_ROOT,
            HelpText = "The root GCP storage folder to publish.")]
        public string Folder { get; set; }

        [Option('c', "count",
            Required = false,
            Default = 1000000,
            HelpText = "The maxium number of files to submit in total")]
        public int MaxSubmissionTotal { get; set; }
    }
}