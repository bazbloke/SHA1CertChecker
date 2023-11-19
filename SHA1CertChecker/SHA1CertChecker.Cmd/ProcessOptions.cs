using CommandLine;
using SHA1CertChecker.Shared;

namespace SHA1CertChecker
{
    [Verb("work", false, new[] { "w" }, HelpText = "Process certificates in GZipped archives files, individually or as a folder.")]
    public class ProcessOptions
    {
        [Option('p', "path",
            Required = true,
            HelpText = "The file or folder containing the certificate data to process.")]
        public string FilePath { get; set; }

        [Option('r', "recurse",
            Required = false,
            Default = false,
            HelpText = "Specifies whether child folders should be included.")]
        public bool RecurseFolders { get; set; }

        [Option('s', "sha1mode",
            Required = false,
            Default = Sha1DcSumRunMode.InProcess,
            HelpText = "Specifies whether the sha1dcsum analysis should be run isolated or in-process.")]
        public Sha1DcSumRunMode RunMode { get; set; }
    }
}