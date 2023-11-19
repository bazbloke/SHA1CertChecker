namespace SHA1CertChecker.Shared
{
    public class Constants
    {
        public const string EVENT_HUB_NAME = "workitems";
        public const string SHA1_COLLISION_DETECTED = "*coll*";
        public const string SHA1_DETECTION_TOOL_PATH = "sha1dcsum.exe";
        public const string CENSYS_APPID_KEY = "CENSYS_APPID";
        public const string CENSYS_SECRET_KEY = "CENSYS_SECRET";
        
        public const string GCP_TOKEN_JSON = "GCP_TOKEN_JSON";
        public const string GCP_DATA_ROOT = "data/";
        
        public const string WORKITEM_QUEUE_LISTEN_CONNECTIONSTRING_KEY = "WorkQueueListenConnectionString";
        public const string WORKITEM_QUEUE_SEND_CONNECTIONSTRING_KEY = "WorkQueueSendConnectionString";

        public const string CERTS_PROCESSED_COUNT = "CertificatesProcessedCount";
        public const string CERTS_PROCESSED_ERROR_COUNT = "CertificatesProcessedErrorCount";
        public const string HASH_COLLISION_FOUND_COUNT = "HashCollisionsFoundCount";
    }
}