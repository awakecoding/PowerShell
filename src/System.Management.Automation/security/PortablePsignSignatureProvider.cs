// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if UNIX
using System.IO;
using System.Management.Automation.Internal;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;

namespace System.Management.Automation
{
    internal static class PortablePsignSignatureProvider
    {
        private const uint StatusOk = 0;
        private const string TrustedCertificatePathsEnv = "PSIGN_POWERSHELL_TRUSTED_CERTIFICATE_PATHS";
        private const string TrustedCertificatesDerBase64Env = "PSIGN_POWERSHELL_TRUSTED_CERTIFICATES_DER_BASE64";
        private const string AnchorDirectoryEnv = "PSIGN_POWERSHELL_ANCHOR_DIRECTORY";
        private const string AuthRootCabEnv = "PSIGN_POWERSHELL_AUTHROOT_CAB";
        private const string AsOfEnv = "PSIGN_POWERSHELL_AS_OF";
        private const string PreferTimestampSigningTimeEnv = "PSIGN_POWERSHELL_PREFER_TIMESTAMP_SIGNING_TIME";
        private const string RequireValidTimestampEnv = "PSIGN_POWERSHELL_REQUIRE_VALID_TIMESTAMP";
        private const string OnlineAiaEnv = "PSIGN_POWERSHELL_ONLINE_AIA";
        private const string OnlineOcspEnv = "PSIGN_POWERSHELL_ONLINE_OCSP";
        private const string RevocationModeEnv = "PSIGN_POWERSHELL_REVOCATION_MODE";
        private const string PsignLibraryName = "psign-core";

        internal static Signature GetSignature(string fileName, byte[] fileContent)
        {
            Utils.CheckArgForNullOrEmpty(fileName, "fileName");

            byte[] content = fileContent;
            if (content == null)
            {
                SecuritySupport.CheckIfFileExists(fileName);
                content = File.ReadAllBytes(fileName);
            }

            PsignPowerShellValidationRequest request = new PsignPowerShellValidationRequest
            {
                SourcePathOrExtension = fileName,
                ContentBase64 = Convert.ToBase64String(content),
                TrustedCertificatePaths = GetPathListEnvironmentVariable(TrustedCertificatePathsEnv),
                TrustedCertificatesDerBase64 = GetListEnvironmentVariable(TrustedCertificatesDerBase64Env),
                AnchorDirectory = GetEnvironmentVariableOrNull(AnchorDirectoryEnv),
                AuthRootCab = GetEnvironmentVariableOrNull(AuthRootCabEnv),
                AsOf = GetEnvironmentVariableOrNull(AsOfEnv),
                PreferTimestampSigningTime = GetBooleanEnvironmentVariable(PreferTimestampSigningTimeEnv),
                RequireValidTimestamp = GetBooleanEnvironmentVariable(RequireValidTimestampEnv),
                OnlineAia = GetBooleanEnvironmentVariable(OnlineAiaEnv),
                OnlineOcsp = GetBooleanEnvironmentVariable(OnlineOcspEnv),
                RevocationMode = GetEnvironmentVariableOrNull(RevocationModeEnv) ?? "Off",
            };

            string requestJson = JsonConvert.SerializeObject(
                request,
                Formatting.None,
                new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
            byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);

            try
            {
                PsignFfiResult result = PsignCoreValidatePowerShellScript(requestBytes, (UIntPtr)requestBytes.Length);
                string responseJson = ReadAndFree(result.Json);
                if (result.StatusCode != StatusOk)
                {
                    PsignErrorResponse error = JsonConvert.DeserializeObject<PsignErrorResponse>(responseJson);
                    return CreateFailure(
                        fileName,
                        SignatureStatus.UnknownError,
                        error?.Message ?? "psign portable signature validation failed.");
                }

                PsignPowerShellValidationResponse response =
                    JsonConvert.DeserializeObject<PsignPowerShellValidationResponse>(responseJson);
                return CreateSignature(fileName, response);
            }
            catch (DllNotFoundException e)
            {
                return CreateFailure(fileName, SignatureStatus.Incompatible, e.Message);
            }
            catch (EntryPointNotFoundException e)
            {
                return CreateFailure(fileName, SignatureStatus.Incompatible, e.Message);
            }
            catch (BadImageFormatException e)
            {
                return CreateFailure(fileName, SignatureStatus.Incompatible, e.Message);
            }
            catch (JsonException e)
            {
                return CreateFailure(fileName, SignatureStatus.UnknownError, e.Message);
            }
        }

        private static Signature CreateSignature(string fileName, PsignPowerShellValidationResponse response)
        {
            if (response == null)
            {
                return CreateFailure(fileName, SignatureStatus.UnknownError, "psign returned an empty validation response.");
            }

            X509Certificate2 signer;
            X509Certificate2 timestamper;
            try
            {
                signer = CreateCertificate(response.SignerCertificateDerBase64);
                timestamper = CreateCertificate(response.TimestamperCertificateDerBase64);
            }
            catch (FormatException e)
            {
                return CreateFailure(fileName, SignatureStatus.UnknownError, e.Message);
            }
            catch (CryptographicException e)
            {
                return CreateFailure(fileName, SignatureStatus.UnknownError, e.Message);
            }

            SignatureStatus status = MapStatus(response.Status, signer);
            Signature signature = new Signature(fileName, status, response.StatusMessage, signer, timestamper)
            {
                SignatureType = status == SignatureStatus.NotSigned ? SignatureType.None : SignatureType.Authenticode,
                PortableTrustVerified = string.Equals(response.TrustStatus, "Valid", StringComparison.OrdinalIgnoreCase),
            };
            return signature;
        }

        private static SignatureStatus MapStatus(string status, X509Certificate2 signer)
        {
            switch (status)
            {
                case "Valid":
                    return SignatureStatus.Valid;
                case "NotSigned":
                    return SignatureStatus.NotSigned;
                case "HashMismatch":
                    return SignatureStatus.HashMismatch;
                case "NotTrusted":
                    return signer == null ? SignatureStatus.UnknownError : SignatureStatus.NotTrusted;
                case "NotSupportedFileFormat":
                    return SignatureStatus.NotSupportedFileFormat;
                case "Incompatible":
                    return SignatureStatus.Incompatible;
                default:
                    return SignatureStatus.UnknownError;
            }
        }

        private static X509Certificate2 CreateCertificate(string certificateDerBase64)
        {
            if (string.IsNullOrEmpty(certificateDerBase64))
            {
                return null;
            }

            return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateDerBase64));
        }

        private static Signature CreateFailure(string fileName, SignatureStatus status, string message)
        {
            return new Signature(fileName, status, message, null, null);
        }

        private static string ReadAndFree(PsignFfiBuffer buffer)
        {
            try
            {
                if (buffer.Ptr == IntPtr.Zero || buffer.Len == UIntPtr.Zero)
                {
                    return string.Empty;
                }

                int length = checked((int)buffer.Len.ToUInt64());
                byte[] jsonBytes = new byte[length];
                Marshal.Copy(buffer.Ptr, jsonBytes, 0, length);
                return Encoding.UTF8.GetString(jsonBytes);
            }
            finally
            {
                PsignCoreFree(buffer);
            }
        }

        private static string[] GetPathListEnvironmentVariable(string name)
        {
            return GetListEnvironmentVariable(name);
        }

        private static string[] GetListEnvironmentVariable(string name)
        {
            string value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(value))
            {
                return Array.Empty<string>();
            }

            string[] entries = value.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < entries.Length; i++)
            {
                entries[i] = entries[i].Trim();
            }

            return entries;
        }

        private static string GetEnvironmentVariableOrNull(string name)
        {
            string value = Environment.GetEnvironmentVariable(name);
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        private static bool GetBooleanEnvironmentVariable(string name)
        {
            string value = Environment.GetEnvironmentVariable(name);
            return bool.TryParse(value, out bool result) && result;
        }

        [DllImport(PsignLibraryName, EntryPoint = "psign_core_validate_powershell_script", CallingConvention = CallingConvention.Cdecl)]
        private static extern PsignFfiResult PsignCoreValidatePowerShellScript(
            byte[] requestJson,
            UIntPtr requestJsonLen);

        [DllImport(PsignLibraryName, EntryPoint = "psign_core_free", CallingConvention = CallingConvention.Cdecl)]
        private static extern void PsignCoreFree(PsignFfiBuffer buffer);

        [StructLayout(LayoutKind.Sequential)]
        private struct PsignFfiBuffer
        {
            internal IntPtr Ptr;
            internal UIntPtr Len;
            internal UIntPtr Cap;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PsignFfiResult
        {
            internal uint StatusCode;
            internal PsignFfiBuffer Json;
        }

        private sealed class PsignPowerShellValidationRequest
        {
            [JsonProperty("source_path_or_extension")]
            public string SourcePathOrExtension { get; set; }

            [JsonProperty("content_base64")]
            public string ContentBase64 { get; set; }

            [JsonProperty("trusted_certificate_paths")]
            public string[] TrustedCertificatePaths { get; set; }

            [JsonProperty("trusted_certificates_der_base64")]
            public string[] TrustedCertificatesDerBase64 { get; set; }

            [JsonProperty("anchor_directory")]
            public string AnchorDirectory { get; set; }

            [JsonProperty("authroot_cab")]
            public string AuthRootCab { get; set; }

            [JsonProperty("as_of")]
            public string AsOf { get; set; }

            [JsonProperty("prefer_timestamp_signing_time")]
            public bool PreferTimestampSigningTime { get; set; }

            [JsonProperty("require_valid_timestamp")]
            public bool RequireValidTimestamp { get; set; }

            [JsonProperty("online_aia")]
            public bool OnlineAia { get; set; }

            [JsonProperty("online_ocsp")]
            public bool OnlineOcsp { get; set; }

            [JsonProperty("revocation_mode")]
            public string RevocationMode { get; set; }
        }

        private sealed class PsignPowerShellValidationResponse
        {
            [JsonProperty("status")]
            public string Status { get; set; }

            [JsonProperty("trust_status")]
            public string TrustStatus { get; set; }

            [JsonProperty("status_message")]
            public string StatusMessage { get; set; }

            [JsonProperty("signer_certificate_der_base64")]
            public string SignerCertificateDerBase64 { get; set; }

            [JsonProperty("timestamper_certificate_der_base64")]
            public string TimestamperCertificateDerBase64 { get; set; }
        }

        private sealed class PsignErrorResponse
        {
            [JsonProperty("message")]
            public string Message { get; set; }
        }
    }
}
#endif
