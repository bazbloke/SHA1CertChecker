using System.Diagnostics;

namespace SHA1CertChecker.Shared
{
    /// <summary>
    /// Performs SHA-1 collision analysis by invoking a new process for each iteration.
    /// </summary>
    public class IsolatedAnalyzer : ICollisionAnalyzer
    {
        public const string SHA1_COLLISION_DETECTED = "*coll*";
        public const string SHA1_DETECTION_TOOL_PATH = ".\\sha1dcsum.exe";

        public async Task<bool> RunAsync(CertificateProcessingRequest request)
        {
            if (!string.IsNullOrEmpty(request.Sha256Hash) &&
                !string.IsNullOrEmpty(request.CertificateBase64Encoded))
            {
                byte[] der = Convert.FromBase64String(request.CertificateBase64Encoded);

                return await EvaluateCollisionAsync(der);
            }

            return false;
        }

        public async Task<bool> EvaluateCollisionAsync(byte[] fileContents)
        {
            string tempFile = Path.GetTempFileName();

            try
            {
                await File.WriteAllBytesAsync(tempFile, fileContents);

                string consoleResults = StartProcess(SHA1_DETECTION_TOOL_PATH, tempFile);

                return !string.IsNullOrEmpty(consoleResults) && consoleResults.Contains(SHA1_COLLISION_DETECTED);
            }
            finally
            {
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                }
            }
        }

        private static string StartProcess(string processFilePath, string tempFile)
        {
            // as per https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standardoutput?view=net-7.0

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = processFilePath,
                Arguments = tempFile,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            string stderr = string.Empty;

            var process = new Process();
            process.StartInfo = startInfo;
            process.ErrorDataReceived += new DataReceivedEventHandler((sender, e) =>
            { stderr += e.Data; });

            process.Start();

            process.BeginErrorReadLine();
            string stdout = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            return $"[stdout]:{stdout}\r\n[stderr]:{stderr}";
        }
    }
}