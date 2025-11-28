// Models/EncryptionAlgorithm.cs
namespace CrossPlatformCryptoTool.Models;

public enum EncryptionAlgorithm
{
    AES,
    SHA256,
    SHA512,
    SM3,
    SM4
}

// Models/KeySize.cs
public enum KeySize
{
    AES128 = 128,
    AES192 = 192,
    AES256 = 256,
    SM4128 = 128
}

// Models/CipherMode.cs
public enum CipherMode
{
    CBC,
    ECB,
    CFB,
    OFB
}

// Models/EncryptionRequest.cs
public class EncryptionRequest
{
    public string InputText { get; set; } = string.Empty;
    public EncryptionAlgorithm Algorithm { get; set; }
    public KeySize KeySize { get; set; }
    public CipherMode Mode { get; set; }
    public string Key { get; set; } = string.Empty;
    public string IV { get; set; } = string.Empty;
    public bool OutputBase64 { get; set; } = true;
}

// Models/EncryptionResult.cs
public class EncryptionResult
{
    public bool Success { get; set; }
    public string Output { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;

    // Base64-encoded key and IV actually used for encryption (if applicable)
    public string UsedKey { get; set; } = string.Empty;
    public string UsedIV { get; set; } = string.Empty;
}