using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Text;

namespace SHA1CertChecker.Shared
{
    public class CertificateProcessingRequest
    {
        private string _sha256Hash;
        private string _sha256HashBase64;

        public CertificateProcessingRequest()
        {
            this._sha256Hash = string.Empty;
            this._sha256HashBase64 = string.Empty;
            this.CertificateBase64Encoded = string.Empty; 
        }

        [JsonProperty("fingerprint_sha256")]
        public string Sha256HashBase64
        {
            get
            {
                return _sha256HashBase64;
            }
            set
            {
                _sha256HashBase64 = value;

                try
                {
                    byte[] data = Convert.FromBase64String(_sha256HashBase64);

                    _sha256Hash = BitConverter.ToString(data).Replace("-", string.Empty).ToLower(); //.PadLeft(64, '0');
                }
                catch (FormatException)
                {
                    _sha256Hash = string.Empty;
                }
            }
        }

        public string Sha256Hash
        {
            get
            {
                return _sha256Hash;
            }
            set
            {
                _sha256Hash = value;
                _sha256HashBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
            }
        }

        [JsonProperty("raw")]
        public string CertificateBase64Encoded { get; set; }

        public static CertificateProcessingRequest Deserialize(string json)
        {            
            return JsonConvert.DeserializeObject<CertificateProcessingRequest>(json);
        }

        public string Serialize()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}