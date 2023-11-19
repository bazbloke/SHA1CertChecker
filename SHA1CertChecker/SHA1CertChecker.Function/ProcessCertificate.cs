using Azure.Messaging.EventHubs;
using Azure.Storage.Blobs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SHA1CertChecker.Shared;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SHA1CertChecker
{
    public class ProcessCertificate
    {
        private readonly IConfiguration _configuration;

        public ProcessCertificate(IConfiguration configuration)
        {
            this._configuration = configuration;
        }

        [FunctionName("ProcessCertificate")]
        public async Task Run(
            [EventHubTrigger(Constants.EVENT_HUB_NAME, Connection = Constants.WORKITEM_QUEUE_LISTEN_CONNECTIONSTRING_KEY)] EventData[] events,
            [Blob("collisions", Connection = "AzureWebJobsStorage")] BlobContainerClient blobContainerClient,
            CancellationToken token,
            ILogger log)
        {
            var exceptions = new List<Exception>();

            CensysClient client = new CensysClient(
                this._configuration[Constants.CENSYS_APPID_KEY],
                this._configuration[Constants.CENSYS_SECRET_KEY]);

            GcpStorage gcpClient = new GcpStorage(this._configuration);
            ICollisionAnalyzer analyzer = new InProcessAnalyzer();
            CertificateProcessor processor = new CertificateProcessor();

            int filesProcessedCount = 0;
            int certsProcessedCount = 0;
            
            foreach (EventData eventData in events)
            {
                Stopwatch timer = new Stopwatch();
                timer.Start();

                string inputFile = eventData.EventBody.ToString();

                string tempFile = Path.GetTempFileName();

                ProcessedFileSummary summary = new ProcessedFileSummary(inputFile);

                try
                {
                    using (var stream = File.OpenWrite(tempFile))
                    {
                        await gcpClient.DownloadFileAsync(inputFile, stream);
                    }

                    summary = await processor.ProcessFile(analyzer, tempFile, token);

                    if (summary.Collisions.Count > 0)
                    {
                        await ReportCollision(blobContainerClient, log, client, summary.Collisions);
                    }

                    if (summary.Exceptions.Count > 0)
                    {
                        foreach (var exception in summary.Exceptions)
                        {
                            log.LogError($"Exception {exception.Message} while processing file {inputFile}");

                            log.LogMetric(Constants.CERTS_PROCESSED_ERROR_COUNT, 1);

                            exceptions.Add(exception);
                        }
                    }

                    filesProcessedCount++;
                    certsProcessedCount = certsProcessedCount + summary.CertificatesAnalyzed;
                }
                catch (Exception e)
                {
                    // We need to keep processing the rest of the batch - capture this exception and continue.
                    // Also, consider capturing details of the message that failed processing so it can be processed again later.
                    exceptions.Add(e);

                    log.LogError($"Exception {e.Message} while processing file {inputFile}");

                    log.LogMetric(Constants.CERTS_PROCESSED_ERROR_COUNT, 1);
                }
                finally
                {
                    if (File.Exists(tempFile))
                    {
                        try
                        {
                            File.Delete(tempFile);
                        }
                        catch (Exception e)
                        {
                            exceptions.Add(e);

                            log.LogInformation($"Exception {e.Message} while attempting to delete file {inputFile}");

                            log.LogMetric(Constants.CERTS_PROCESSED_ERROR_COUNT, 1);
                        }
                    }
                }

                timer.Stop();
                log.LogInformation($"Finished processing {summary.CertificatesAnalyzed} certs from {inputFile} in {timer.ElapsedMilliseconds}ms");

                await Task.Yield();
            }

            log.LogMetric(Constants.CERTS_PROCESSED_COUNT, certsProcessedCount);

            log.LogInformation($"Processed batch of {filesProcessedCount} files with {certsProcessedCount} certificates");

            // Once processing of the batch is complete, if any messages in the batch failed processing throw an exception so that there is a record of the failure.
            if (exceptions.Count > 1)
                throw new AggregateException(exceptions);

            if (exceptions.Count == 1)
                throw exceptions.Single();
        }

        private static async Task ReportCollision(BlobContainerClient blobContainerClient, ILogger log, CensysClient client, IEnumerable<CertificateProcessingRequest> collisions)
        {
            foreach (var request in collisions)
            {
                BlobClient blobClient = blobContainerClient.GetBlobClient(request.Sha256Hash + ".json");

                string json = await client.GetCertificateJson(request.Sha256Hash);
                using (MemoryStream writeStream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    await blobClient.UploadAsync(writeStream);
                }
                log.LogMetric(Constants.HASH_COLLISION_FOUND_COUNT, 1);

                log.LogCritical($"Found a collision for hash: {request.Sha256Hash}");
            }
        }
    }
}
