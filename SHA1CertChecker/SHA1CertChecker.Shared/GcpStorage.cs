using Google.Cloud.Storage.V1;
using Microsoft.Extensions.Configuration;

namespace SHA1CertChecker.Shared
{
    public class GcpStorage
    {
        public const string ENVIRONMENT_VARIABLE_NAME = "GOOGLE_APPLICATION_CREDENTIALS";
        public const string BUCKET_NAME = "sha1certchecker";

        private readonly StorageClient _client;

        public GcpStorage(IConfiguration configuration)
        {
            if (Environment.GetEnvironmentVariable(ENVIRONMENT_VARIABLE_NAME) == null)
            {
                string keyFile = Path.GetTempFileName();

                File.WriteAllText(keyFile, configuration[Constants.GCP_TOKEN_JSON]);

                Environment.SetEnvironmentVariable(ENVIRONMENT_VARIABLE_NAME, keyFile);
            };

            _client = StorageClient.Create();
        }

        public IEnumerable<string> EnumerateFiles(string filter)
        {
            var files = _client.ListObjects(BUCKET_NAME, filter);

            foreach (var file in files)
            {
                // is it a folder?
                string[] tokens = file.Name.Split('/');
                if (tokens.Length > 1 && tokens[1] != string.Empty)
                {
                    yield return file.Name;
                }
            }
        }

        public async Task DownloadFileAsync(string sourcePath, Stream stream)
        {
            await _client.DownloadObjectAsync(BUCKET_NAME, sourcePath, stream);
        }
    }
}
