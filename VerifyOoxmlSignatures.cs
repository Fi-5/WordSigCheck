using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

public class VerifyOoxmlSignatures
{
    private readonly ILogger<VerifyOoxmlSignatures> _log;

    public VerifyOoxmlSignatures(ILogger<VerifyOoxmlSignatures> log)
    {
        _log = log;
    }

    [Function("VerifyOoxmlSignatures")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        Input? input;
        try
        {
            input = await JsonSerializer.DeserializeAsync<Input>(req.Body, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Invalid JSON input");
            return await Bad(req, "Invalid JSON");
        }

        if (input is null || string.IsNullOrWhiteSpace(input.FileContentBase64))
            return await Bad(req, "Missing fileContentBase64");

        byte[] fileBytes;
        try { fileBytes = Convert.FromBase64String(input.FileContentBase64); }
        catch { return await Bad(req, "fileContentBase64 is not valid base64"); }

        if (fileBytes.Length < 4 || fileBytes[0] != 0x50 || fileBytes[1] != 0x4B)
            return await Bad(req, "Not a ZIP/OOXML file");

        var signatures = new List<SignatureResult>();

        using var ms = new MemoryStream(fileBytes, writable: false);
        using var package = Package.Open(ms, FileMode.Open, FileAccess.Read);

        var dsm = new PackageDigitalSignatureManager(package);

        int i = 0;
        foreach (var sig in dsm.Signatures)
        {
            var r = new SignatureResult { Index = i++ };

            try
            {
                r.PackageSignatureValid = sig.Verify() == VerifyResult.Success;
            }
            catch (Exception ex)
            {
                r.PackageSignatureValid = false;
                r.Errors.Add("Package signature verify failed: " + ex.Message);
            }

            X509Certificate2? signerCert = null;
            try
            {
                signerCert = TryGetSignerCert(sig, r);

                if (signerCert != null)
                {
                    r.Signer.Subject = ParseDistinguishedName(signerCert.SubjectName, signerCert.Subject);
                    r.Signer.Issuer = ParseDistinguishedName(signerCert.IssuerName, signerCert.Issuer);

                    r.Signer.Thumbprint = signerCert.Thumbprint ?? "";
                    r.Signer.SerialNumber = signerCert.SerialNumber ?? "";
                    r.Signer.Sha256Fingerprint = Sha256Hex(signerCert.RawData);
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(r.Signer.Issuer.Raw) && string.IsNullOrWhiteSpace(r.Signer.SerialNumber))
                        r.Errors.Add("Signer certificate not found (not embedded and not resolvable).");
                }
            }
            catch (Exception ex)
            {
                r.Errors.Add("Failed to read signer certificate: " + ex.Message);
            }

            if (signerCert != null)
            {
                try
                {
                    using var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

                    r.CertificateChainValid = chain.Build(signerCert);
                    r.RevocationChecked = true;

                    if (!r.CertificateChainValid)
                    {
                        foreach (var st in chain.ChainStatus)
                            r.Errors.Add($"Chain: {st.Status} - {st.StatusInformation}".Trim());
                    }
                }
                catch (Exception ex)
                {
                    r.CertificateChainValid = false;
                    r.RevocationChecked = false;
                    r.Errors.Add("Chain/revocation check failed: " + ex.Message);
                }
            }
            else
            {
                r.CertificateChainValid = false;
                r.RevocationChecked = false;
            }

            signatures.Add(r);
        }

        var output = new Output
        {
            Format = "OOXML_DOCX",
            Signatures = signatures,
            AllValid = signatures.Count > 0 && signatures.All(s => s.PackageSignatureValid && s.CertificateChainValid)
        };

        var json = JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true });
        _log.LogInformation("Verify result:\n{json}", json);

        var res = req.CreateResponse(HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await res.WriteStringAsync(json);
        return res;
    }

    private static X509Certificate2? TryGetSignerCert(PackageDigitalSignature sig, SignatureResult r)
    {
        r.CertificateEmbeddingOption = sig.CertificateEmbeddingOption.ToString();
        r.SignaturePartUri = sig.SignaturePart?.Uri.ToString() ?? "";

        if (sig.Signer != null)
            return new X509Certificate2(sig.Signer);

        try
        {
            var ki = sig.Signature?.KeyInfo;
            if (ki != null)
            {
                r.KeyInfoClauseCount = ki.Count;

                foreach (KeyInfoClause clause in ki)
                {
                    if (clause is KeyInfoX509Data x509)
                    {
                        r.KeyInfoHasX509Data = true;

                        foreach (var c in x509.Certificates)
                            if (c is X509Certificate cert)
                                return new X509Certificate2(cert);

                        foreach (X509IssuerSerial iser in x509.IssuerSerials)
                        {
                            r.Signer.Issuer = ParseDistinguishedName(null, iser.IssuerName ?? "");
                            r.Signer.SerialNumber = iser.SerialNumber ?? "";
                            r.Errors.Add("Certificate not embedded; only Issuer/Serial present in KeyInfo.");
                            break;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            r.Errors.Add("KeyInfo parse failed: " + ex.Message);
        }

        try
        {
            const string relType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate";
            var sigPart = sig.SignaturePart;

            if (sigPart != null)
            {
                var rel = sigPart.GetRelationshipsByType(relType).FirstOrDefault();
                r.HasCertificatePartRelationship = rel != null;

                if (rel != null)
                {
                    var certPartUri = PackUriHelper.ResolvePartUri(sigPart.Uri, rel.TargetUri);
                    var certPart = sigPart.Package.GetPart(certPartUri);

                    using var s = certPart.GetStream(FileMode.Open, FileAccess.Read);
                    using var tmp = new MemoryStream();
                    s.CopyTo(tmp);

                    return new X509Certificate2(tmp.ToArray());
                }
            }
        }
        catch (Exception ex)
        {
            r.Errors.Add("Certificate part read failed: " + ex.Message);
        }

        try
        {
            var sigPart = sig.SignaturePart;
            if (sigPart != null)
            {
                using var s = sigPart.GetStream(FileMode.Open, FileAccess.Read);
                var xdoc = XDocument.Load(s);

                XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";

                var x509CertB64 = xdoc.Descendants(ds + "X509Certificate").FirstOrDefault()?.Value;
                if (!string.IsNullOrWhiteSpace(x509CertB64))
                {
                    var raw = Convert.FromBase64String(x509CertB64);
                    return new X509Certificate2(raw);
                }

                var issuerName = xdoc.Descendants(ds + "X509IssuerName").FirstOrDefault()?.Value ?? "";
                var serial = xdoc.Descendants(ds + "X509SerialNumber").FirstOrDefault()?.Value ?? "";

                if (!string.IsNullOrWhiteSpace(issuerName))
                    r.Signer.Issuer = ParseDistinguishedName(null, issuerName);

                if (!string.IsNullOrWhiteSpace(serial))
                    r.Signer.SerialNumber = serial;

                if (!string.IsNullOrWhiteSpace(r.Signer.Issuer.Raw) || !string.IsNullOrWhiteSpace(r.Signer.SerialNumber))
                    r.Errors.Add("Certificate not present in signature XML; only Issuer/Serial found.");
                else
                    r.Errors.Add("No X509Certificate and no Issuer/Serial in signature XML.");
            }
        }
        catch (Exception ex)
        {
            r.Errors.Add("Signature XML read/parse failed: " + ex.Message);
        }

        return null;
    }

    private static DistinguishedNameInfo ParseDistinguishedName(X500DistinguishedName? dn, string rawFallback)
    {
        var raw = string.IsNullOrWhiteSpace(rawFallback) ? "" : rawFallback;

        string formatted;
        try
        {
            formatted = dn != null ? dn.Format(true) : raw;
            if (string.IsNullOrWhiteSpace(formatted))
                formatted = raw;
        }
        catch
        {
            formatted = raw;
        }

        var info = new DistinguishedNameInfo
        {
            Raw = raw,
            Formatted = formatted
        };

        foreach (var pair in TokenizeDn(formatted))
        {
            info.Rdn.Add(pair);

            // ByType: vždy list (správně pro obecný případ)
            if (!info.ByType.TryGetValue(pair.Type, out var list))
            {
                list = new List<string>();
                info.ByType[pair.Type] = list;
            }
            list.Add(pair.Value);

            // Single: první hodnota jako string (komfortní)
            if (!info.Single.ContainsKey(pair.Type))
                info.Single[pair.Type] = pair.Value;
        }

        return info;
    }

    private static IEnumerable<DnAttribute> TokenizeDn(string dnText)
    {
        if (string.IsNullOrWhiteSpace(dnText))
            yield break;

        var s = dnText.Replace("\r\n", "\n").Replace('\r', '\n');

        foreach (var token in SplitUnescaped(s, new[] { '\n', ',', ';', '+' }))
        {
            var t = token.Trim();
            if (t.Length == 0) continue;

            var idx = t.IndexOf('=');
            if (idx <= 0) continue;

            var type = t.Substring(0, idx).Trim().ToUpperInvariant();
            var value = t.Substring(idx + 1).Trim();

            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
                value = value.Substring(1, value.Length - 2);

            value = UnescapeDnValue(value);

            yield return new DnAttribute { Type = type, Value = value };
        }
    }

    private static IEnumerable<string> SplitUnescaped(string input, char[] seps)
    {
        var buf = new System.Text.StringBuilder();
        bool inQuotes = false;
        bool esc = false;

        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];

            if (esc)
            {
                buf.Append(c);
                esc = false;
                continue;
            }

            if (c == '\\')
            {
                buf.Append(c);
                esc = true;
                continue;
            }

            if (c == '"')
            {
                inQuotes = !inQuotes;
                buf.Append(c);
                continue;
            }

            if (!inQuotes && seps.Contains(c))
            {
                yield return buf.ToString();
                buf.Clear();
                continue;
            }

            buf.Append(c);
        }

        if (buf.Length > 0)
            yield return buf.ToString();
    }

    private static string UnescapeDnValue(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;

        var sb = new System.Text.StringBuilder(value.Length);
        bool esc = false;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!esc)
            {
                if (c == '\\')
                {
                    esc = true;
                    continue;
                }
                sb.Append(c);
            }
            else
            {
                sb.Append(c);
                esc = false;
            }
        }

        return sb.ToString();
    }

    private static async Task<HttpResponseData> Bad(HttpRequestData req, string msg)
    {
        var res = req.CreateResponse(HttpStatusCode.BadRequest);
        await res.WriteStringAsync(msg);
        return res;
    }

    public class Input
{
    public string FileName { get; set; } = "";
    public string FileContentBase64 { get; set; } = "";
}


    public class Output
    {
        public string Format { get; set; } = "";
        public List<SignatureResult> Signatures { get; set; } = new();
        public bool AllValid { get; set; }
    }

    public class SignatureResult
    {
        public int Index { get; set; }
        public bool PackageSignatureValid { get; set; }
        public bool CertificateChainValid { get; set; }
        public bool RevocationChecked { get; set; }

        public string CertificateEmbeddingOption { get; set; } = "";

        public string SignaturePartUri { get; set; } = "";
        public int KeyInfoClauseCount { get; set; }
        public bool KeyInfoHasX509Data { get; set; }
        public bool HasCertificatePartRelationship { get; set; }

        public SignerInfo Signer { get; set; } = new();
        public List<string> Errors { get; set; } = new();
    }

    public class SignerInfo
    {
        public DistinguishedNameInfo Subject { get; set; } = new();
        public DistinguishedNameInfo Issuer { get; set; } = new();

        public string Thumbprint { get; set; } = "";
        public string SerialNumber { get; set; } = "";
        public string Sha256Fingerprint { get; set; } = "";
    }

    public class DistinguishedNameInfo
    {
        public string Raw { get; set; } = "";
        public string Formatted { get; set; } = "";

        public List<DnAttribute> Rdn { get; set; } = new();

        // obecně správně (může být více hodnot pro stejný typ)
        public Dictionary<string, List<string>> ByType { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        // komfortní přístup: první hodnota jako string
        public Dictionary<string, string> Single { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public class DnAttribute
    {
        public string Type { get; set; } = "";
        public string Value { get; set; } = "";
    }
private static string ToHex(byte[] bytes) =>
    BitConverter.ToString(bytes).Replace("-", "");

private static string Sha256Hex(byte[] data)
{
    using (var sha = SHA256.Create())
        return ToHex(sha.ComputeHash(data));
}
}

#if NET48
namespace System.Runtime.CompilerServices
{
    // potřeba pro init/record v C# 9+ na net48
    public sealed class IsExternalInit { }
}
#endif
