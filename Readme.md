# SHA1CertChecker
A massively scaleable cloud-hosted scanner for SHA-1 thumbprint collision detection in certificates file. 

The solution is designed to orchestrate scans hosted in Microsoft's Azure cloud using C# and .Net (my skillset). Certificate data is provided by Censys and found in Google Cloud's Big Query platform.

By Barry Markey, 2023. Published under the terms of the MIT License.

# Key Components

## SHA1CertChecker.Shared
Common code lib shared between the Azure function and commond-line tool.

## SHA1CertChecker.Test
The unit test suite.

## SHA1CertChecker.Function
An Azure Function designed to operate the analysis at cloud scale. 

## SHA1CertChecker.Cmd
A command-line tool to automate the certificate analysis process. Supported verbs allow for the submission of certificate data to the function worker pool and local analysis of a set of certificates.

## Example Commands
```
.\SHA1CertChecker.Cmd.exe
SHA1CertChecker.Cmd 1.0.0
Copyright (C) 2023 SHA1CertChecker.Cmd

ERROR(S):
  No verb selected.

  work, w    Process certificates in GZipped archives files, individually or as a folder.

  add, a     Add a workitem to the queue.

  help       Display more information on a specific command.

  version    Display version information.

.\SHA1CertChecker.Cmd.exe work --help
SHA1CertChecker.Cmd 1.0.0
Copyright (C) 2023 SHA1CertChecker.Cmd

ERROR(S):
  Required option 'p, path' is missing.

  -p, --path        Required. The file or folder containing the certificate data to process.

  -r, --recurse     (Default: false) Specifies whether child folders should be included.

  -s, --sha1mode    (Default: InProcess) Specifies whether the sha1dcsum analysis should be run isolated or in-process.

  --help            Display this help screen.

  --version         Display version information.

.\SHA1CertChecker.Cmd.exe add --help
SHA1CertChecker.Cmd 1.0.0
Copyright (C) 2023 SHA1CertChecker.Cmd

  -f, --folder    (Default: data/) The root GCP storage folder to publish.

  -c, --count     (Default: 1000000) The maxium number of files to submit in total

  --help          Display this help screen.

  --version       Display version information.
```

## Source Data
It is expected the input list of certificates to process will be sourced from a Google Cloud Storage bucket that you own. The bucket will contain a series of JSON (newline delimited) files with data sourced from the censys-io.research_1m.certificatesv2 curated dataset hosted in Google's Big Query platform. See https://support.censys.io/hc/en-us/articles/360038761891-Research-Access-to-Censys-Data for details on data access.

The data is expected to reside in a Google Cloud storage bucket named 'data' and should be GZipped into JSON. This was chosen since it was the best option offered by the Big Query Export feature. The size of the files is dynamically chosen by Big Query at the time of export. Depending on how much data is selected, file sizes may vary between 40mb and 130mb. Partitioning the source data into sets of 1 billion rows seemed effective.

Each row of the input data should follow this schema which closely matches the naming convention of the original data in the Censys certificatesv2 dataset:

	{"fingerprint_sha256": "[Bas64 Encoded Hash]","raw": "[Base64Encoded Cert Data]"}

This query was used to select the overall set of certificates. As of November 2023 it returned 3.2 billion rows.

```
SELECT
  fingerprint_sha256,
  raw
FROM
  `censys-io.research_1m.certificates_v2`
  WHERE 
    parsed.validity_period.not_before >= TIMESTAMP('2023-01-01') AND
    added_at >= TIMESTAMP('2023-01-01')
```

## Dependencies
This essence of this project is a means to automate the analysis of raw certificate .DER files looking for tell-tale signs the file was crafted to produce a given SHA-1 hash thumbprint.

The core analysis logic is performed by the sha1dcsum tool, copyright 2017 by Marc Stevens, CWI Amsterdam and Dan Shumow, Microsoft Research.

The code for this project can be found at https://github.com/cr-marcstevens/sha1collisiondetection

For performance reasons, SHA1CertChecker takes a binary dependency on the sha1dcsum tool. To achieve this it was necessary to recompile the code as a .DLL and also needed a few changes to the function definitions in sha1.h, as follows:

```
__declspec(dllexport) void __cdecl SHA1DCInit(SHA1_CTX*);

__declspec(dllexport) void __cdecl SHA1DCSetSafeHash(SHA1_CTX*, int);

__declspec(dllexport) void __cdecl  SHA1DCUpdate(SHA1_CTX*, const char*, size_t);

__declspec(dllexport) int __cdecl SHA1DCFinal(unsigned char[20], SHA1_CTX*);
```

For full transparency, the SHA1CertChecker project also supports running the original sha1dcsum.exe exeutable unaltered, but the performance hit is significant.


## Gratitude
Special thanks to Ryan Farrell and the team at Censys for their invaluable help and support in creating this project. 

A debt is owed to Marc Stevens and Dan Shumow for their tooling and research that inspired this effort. See https://www.microsoft.com/en-us/research/publication/are-certificate-thumbprints-unique/