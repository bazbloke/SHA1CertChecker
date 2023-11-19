using CommandLine;
using Microsoft.Extensions.Configuration;
using SHA1CertChecker.Shared;
using System.Diagnostics;
using System.Text;

namespace SHA1CertChecker
{
    public partial class Program
    {
        private static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        public static void Main(string[] args)
        {
            var builder = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .AddUserSecrets<Program>();
            IConfiguration configuration = builder.Build();

            //var args2 = new[] { "work", "-p", "d:\\sans\\data\\done\\Certs2023Bucket2-10000000000000.gz"};

            Parser.Default.ParseArguments<ProcessOptions, PublishOptions>(args)
              .MapResult(
                (ProcessOptions options) => RunAsync(options).Result,
                (PublishOptions options) => PublishWorkitemsAsync(options, configuration).Result,
                errors => 1);
        }

        private static void DisplayElapsedTime(Stopwatch timer)
        {
            TimeSpan ts = timer.Elapsed;

            string elapsedTime = string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours,
                ts.Minutes,
                ts.Seconds,
                ts.Milliseconds / 10);

            Console.WriteLine($"[*] Done in {elapsedTime}");
        }

        private static void WriteProgressToConsole(int progress)
        {
            Console.CursorLeft = 0;
            Console.Write($"[+] Sent: {progress}");
        }

        private async static Task<int> PublishWorkitemsAsync(PublishOptions options, IConfiguration configuration)
        {
            Console.WriteLine($"[+] Publishing certificates from folder: {options.Folder}");
            Console.WriteLine($"[+] Max submission count: {options.MaxSubmissionTotal}");

            CancellationToken token = ListenForUserCancel();

            string connectionString = configuration[Constants.WORKITEM_QUEUE_SEND_CONNECTIONSTRING_KEY];

            var queue = new WorkItemQueue(
                connectionString,
                Constants.EVENT_HUB_NAME);

            int itemNumber = 0;
            int batchesSubmitted = 0;

            StringBuilder builder = new StringBuilder();

            Stopwatch timer = new Stopwatch();
            timer.Start();

            GcpStorage gcpStorage = new GcpStorage(configuration);

            try
            {
                foreach (string file in gcpStorage.EnumerateFiles(options.Folder))
                {
                    if (token.IsCancellationRequested || itemNumber == options.MaxSubmissionTotal)
                    {
                        break;
                    }

                    itemNumber++;

                    await queue.Publish(file);
                    batchesSubmitted++;

                    WriteProgressToConsole(batchesSubmitted);

                    builder.Clear();
                }

                Console.CursorLeft = 0;
                Console.WriteLine($"[+] Added {itemNumber} workitems to the queue in {batchesSubmitted} batches.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ERROR: {ex}");

                Environment.ExitCode = -1;
            }

            timer.Stop();
            DisplayElapsedTime(timer);

            return 0;
        }

        private async static Task<int> RunAsync(ProcessOptions options)
        {
            Console.WriteLine($"[+] Processing certificates from: {options.FilePath}");

            CertificateProcessor archive = new CertificateProcessor();
            archive.FileProcessedStatusCallback = (int progress, string context) =>
            {
                Console.CursorLeft = 0;
                Console.Write($"[+] Processed: {progress} ({context})");
            };

            CancellationToken token = ListenForUserCancel();
            List<ProcessedFileSummary> processSummaries = new List<ProcessedFileSummary>();

            Stopwatch timer = new Stopwatch();
            timer.Start();
            try
            {
                ICollisionAnalyzer analyzer = options.RunMode == Sha1DcSumRunMode.InProcess ? new InProcessAnalyzer() : new IsolatedAnalyzer();

                if (Directory.Exists(options.FilePath))
                {
                    foreach (var file in Directory.GetFiles(options.FilePath, "*.*", options.RecurseFolders ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly))
                    {
                        if (token.IsCancellationRequested)
                        {
                            break;
                        }

                        Console.CursorLeft = 0;
                        Console.WriteLine($"[+] {file}                                                     ");
                        processSummaries.Add(await archive.ProcessFile(analyzer, file, token));
                    }
                }
                else
                {
                    Console.CursorLeft = 0;
                    Console.WriteLine($"[+] {options.FilePath}                                                     ");
                    processSummaries.Add(await archive.ProcessFile(analyzer, options.FilePath, token));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ERROR: {ex}");

                Environment.ExitCode = -1;
            }

            int fileCount = processSummaries.Count();
            int certificateCount = processSummaries.Sum(s => s.CertificatesAnalyzed);
            int collisionsFound = processSummaries.Sum(s => s.Collisions.Count);
            int exceptionsThrown = processSummaries.Sum(s => s.Exceptions.Count);

            Console.CursorLeft = 0;
            Console.WriteLine($"[+] Processed {fileCount} files, {certificateCount} certificates and found {collisionsFound} collisions.                                ");
            Console.WriteLine($"[+] {exceptionsThrown} errors were encountered.");

            if (collisionsFound > 0)
            {
                foreach (var certificate in processSummaries.SelectMany(s => s.Collisions))
                {
                    Console.WriteLine($"[!] Collision found with hash: {certificate.Sha256Hash}");
                }
            }

            if (exceptionsThrown > 0)
            {
                foreach (var summary in processSummaries.Where(s => s.Exceptions.Count > 0))
                {
                    foreach (var exception in summary.Exceptions)
                    {
                        Console.WriteLine($"[!] Exception thrown in {summary.FilePath} with message: {exception.Message}");
                    }
                }
            }

            timer.Stop();
            DisplayElapsedTime(timer);

            return 0;
        }

        private static CancellationToken ListenForUserCancel()
        {
            Task consoleListen = new Task(() =>
            {
                Console.Read();
                Console.WriteLine("[*] User requested stop.");

                cancellationTokenSource.Cancel();
            });

            consoleListen.Start();

            return cancellationTokenSource.Token;
        }
    }
}