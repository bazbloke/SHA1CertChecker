using SHA1CertChecker.Shared;

namespace SHA1CertChecker.Tests
{
    [TestClass]
    public class CertificateProcessingRequestTests
    {
        [TestMethod]
        public void CertificateProcessingRequest_remembers_properties()
        {
            // Arrange

            // Act
            CertificateProcessingRequest req = new CertificateProcessingRequest
            {
                CertificateBase64Encoded = "Expected Value",
                Sha256Hash = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc"
            };

            // Assert
            Assert.AreEqual("a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc", req.Sha256Hash);
            Assert.AreEqual("Expected Value", req.CertificateBase64Encoded);
        }

        [TestMethod]
        public void CertificateProcessingRequest_roundtrips_serialization()
        {
            // Arrange
            CertificateProcessingRequest req = new CertificateProcessingRequest
            {
                CertificateBase64Encoded = "Expected Value",
                Sha256Hash = "a6e9cab4fe5c2727aabcaca572c6618d62d1f6fce49b25f3dd7d723e05088ecc"
            };

            // Act
            var req2 = CertificateProcessingRequest.Deserialize(req.Serialize());

            // Assert
            Assert.AreEqual(req.Sha256Hash, req2.Sha256Hash);
            Assert.AreEqual(req.CertificateBase64Encoded, req2.CertificateBase64Encoded);
        }


        [TestMethod]
        public void CertificateProcessingRequest_deserialization_unpacks_base64_encoded_hashes()
        {
            // Arrange            
            var req = CertificateProcessingRequest.Deserialize("{\"fingerprint_sha256\": \"ErBp3PS7/F2SpYBK3K2fd47Rc1UEiuQg6dYPymaLDwc=\",\"raw\": \"MIIE/DCCA+SgAwIBAgISA/lcPD8/anpyDU4TocwEPxTiMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzA5MjIwMTQxMzJaFw0yMzEyMjEwMTQxMzFaMCMxITAfBgNVBAMTGGZvcm1hdGlvbi5mYXN0bGVhcm5lci5mcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7wJvQ0tAkXP3ktGTCa+uQ41MpOJ1NJepNvWFCpheGHVvTOg4atchRPwyAC66DKHxtFbidC6xQAIgfIU+HEDb7AM4UArvP/Ag6fWYJZKw9FIM491sQJ5cs7gPIBl/c8IuRMaxfD8BUZwtyNsm78YFv0IFfjwgAJWm+VEMiV8FMAw1D4daQx4t9gM19Sqmt0ZaAywRIPIYFh2vxSUihNhnbZ2h8TYaDCzEo9nkm+uiJddORnNrpr3K/mDzjPK8Vaf6EkPt0E0KlQhbBGqV35tMxNrxg6YcOIKhLayrNVmDrgU6ZnY5i/staV4m7D0sS6rB1y1y+7SYlF9+0z04tVWacCAwEAAaOCAhkwggIVMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUqidXA5YYsrcjCPfquu32PIDbtKkwHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wIwYDVR0RBBwwGoIYZm9ybWF0aW9uLmZhc3RsZWFybmVyLmZyMBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGKusONXgAABAMARzBFAiEAoMtsUZrVmF/yhokbXQZMACGJQPUSz2cULq15ZBKEqwkCIEMItkHDpuqwMpMBK0M1NnRXyJaMZy83VIiVJezX5UXVAHUA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAGKusONUwAABAMARjBEAiBi3/U74xUM1OPpop0g9Q9KQBWISwphfpNb7Wp1VmJyZgIgXjbHaMwE+xy8zhRij2FasPiXB281JNbP6ePw4+9T4/IwDQYJKoZIhvcNAQELBQADggEBADBNDNYtknlw+qLGor60J5nuQZjXV1efs480aJI9oeKHPnJWN+GZyN0GMSMBSIYKpr/M8pU8kBtssUeg6M3pIWubfzBZ6KwEGRF47zet71+gtv1DcHI67t1zltU+kAgtU6PbjmN3k/edk1cq7ODuvp3BfmXtjvM8rwJpXUHZ+yb0CmktswuHs2tqJ47PGfURy8aKEeAeV0Ivm3H9q6sEAPjC6HaEEcSCEsOYzXGkZQVRPjEAdcmpUrF9N08KhFRwSU2qMQJWHmAdwo9+GC0moCVDNt0xtOYAbaqUQ28nu+5vxRJdW6n/FaoNI10x1TsghyPbtcHPYoX0ITVikZd2iwg=\"}");

            // Assert
            Assert.AreEqual("12b069dcf4bbfc5d92a5804adcad9f778ed17355048ae420e9d60fca668b0f07", req.Sha256Hash);
            Assert.AreEqual("ErBp3PS7/F2SpYBK3K2fd47Rc1UEiuQg6dYPymaLDwc=", req.Sha256HashBase64);            
        }
    }
}