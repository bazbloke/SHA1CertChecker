using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;
using System.IO.Compression;
using System.Text;

namespace SHA1CertChecker.Shared
{
    public class WorkItemQueue
    {
        private readonly string _hubName;
        private readonly string _connectionString;

        public WorkItemQueue(string connectionString, string hubName)
        {
            this._hubName = hubName;
            this._connectionString = connectionString;
        }

        public async Task Publish(string request)
        {
            EventHubProducerClient producerClient = new EventHubProducerClient(
                this._connectionString,
                this._hubName);

            // Create a batch of events 
            using (EventDataBatch eventBatch = await producerClient.CreateBatchAsync())
            {
                if (!eventBatch.TryAdd(new EventData(request)))
                {
                    // if it is too large for the batch
                    throw new Exception($"Event cannot be sent.");
                }

                try
                {
                    // Use the producer client to send the batch of events to the event hub
                    await producerClient.SendAsync(eventBatch);

                }
                finally
                {
                    await producerClient.DisposeAsync();
                }

            }
        }
    }
}