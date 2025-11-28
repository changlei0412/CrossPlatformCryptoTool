// Services/EncryptionService.cs
using CrossPlatformCryptoTool.Models;
using CrossPlatformCryptoTool.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using System.Text;
using CipherMode = CrossPlatformCryptoTool.Models.CipherMode;

public class EncryptionService : IEncryptionService
{
    public EncryptionResult Encrypt(EncryptionRequest request)
    {
        try
        {
            return request.Algorithm switch
            {
                EncryptionAlgorithm.AES => EncryptAes(request),
                EncryptionAlgorithm.SHA256 => HashSha256(request),
                EncryptionAlgorithm.SHA512 => HashSha512(request),
                EncryptionAlgorithm.SM3 => HashSm3(request),
                EncryptionAlgorithm.SM4 => EncryptSm4(request),
                _ => new EncryptionResult { Success = false, ErrorMessage = "不支持的算法" }
            };
        }
        catch (Exception ex)
        {
            return new EncryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    public EncryptionResult Decrypt(EncryptionRequest request)
    {
        try
        {
            return request.Algorithm switch
            {
                EncryptionAlgorithm.AES => DecryptAes(request),
                EncryptionAlgorithm.SM4 => DecryptSm4(request),
                EncryptionAlgorithm.SHA256 => new EncryptionResult { Success = false, ErrorMessage = "哈希算法不可逆" },
                EncryptionAlgorithm.SHA512 => new EncryptionResult { Success = false, ErrorMessage = "哈希算法不可逆" },
                EncryptionAlgorithm.SM3 => new EncryptionResult { Success = false, ErrorMessage = "哈希算法不可逆" },
                _ => new EncryptionResult { Success = false, ErrorMessage = "不支持的算法" }
            };
        }
        catch (Exception ex)
        {
            return new EncryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private EncryptionResult EncryptAes(EncryptionRequest request)
    {
        using var aes = Aes.Create();
        aes.KeySize = (int)request.KeySize;
        aes.Mode = GetAesCipherMode(request.Mode);
        aes.Padding = PaddingMode.PKCS7;

        byte[] usedKeyBytes;
        byte[] usedIvBytes;

        //处理密钥
        if (string.IsNullOrEmpty(request.Key))
        {
            aes.GenerateKey();
            usedKeyBytes = aes.Key;
        }
        else
        {
            usedKeyBytes = GetKeyBytes(request.Key, aes.KeySize / 8);
            aes.Key = usedKeyBytes;
        }

        //处理IV
        if (string.IsNullOrEmpty(request.IV))
        {
            aes.GenerateIV();
            usedIvBytes = aes.IV;
        }
        else
        {
            usedIvBytes = GetKeyBytes(request.IV, aes.BlockSize / 8);
            aes.IV = usedIvBytes;
        }

        using var encryptor = aes.CreateEncryptor();
        var inputBytes = Encoding.UTF8.GetBytes(request.InputText);
        var encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);

        var resultText = request.OutputBase64
 ? Convert.ToBase64String(encryptedBytes)
 : BitConverter.ToString(encryptedBytes).Replace("-", "");

        return new EncryptionResult
        {
            Success = true,
            Output = resultText,
            UsedKey = Convert.ToBase64String(usedKeyBytes),
            UsedIV = Convert.ToBase64String(usedIvBytes)
        };
    }

    private EncryptionResult DecryptAes(EncryptionRequest request)
    {
        using var aes = Aes.Create();
        aes.KeySize = (int)request.KeySize;
        aes.Mode = GetAesCipherMode(request.Mode);
        aes.Padding = PaddingMode.PKCS7;

        // 获取 Key/IV
        if (string.IsNullOrEmpty(request.Key) || string.IsNullOrEmpty(request.IV))
        {
            return new EncryptionResult { Success = false, ErrorMessage = "解密需要 Key 和 IV" };
        }

        aes.Key = GetKeyBytes(request.Key, aes.KeySize / 8);
        aes.IV = GetKeyBytes(request.IV, aes.BlockSize / 8);

        using var decryptor = aes.CreateDecryptor();
        byte[] cipherBytes = request.OutputBase64 ? Convert.FromBase64String(request.InputText) : HexStringToBytes(request.InputText);
        var decrypted = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        var resultText = Encoding.UTF8.GetString(decrypted);
        return new EncryptionResult { Success = true, Output = resultText };
    }

    private EncryptionResult HashSha256(EncryptionRequest request)
    {
        using var sha256 = SHA256.Create();
        var inputBytes = Encoding.UTF8.GetBytes(request.InputText);
        var hashBytes = sha256.ComputeHash(inputBytes);

        var result = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        return new EncryptionResult { Success = true, Output = result };
    }

    private EncryptionResult HashSha512(EncryptionRequest request)
    {
        using var sha512 = SHA512.Create();
        var inputBytes = Encoding.UTF8.GetBytes(request.InputText);
        var hashBytes = sha512.ComputeHash(inputBytes);

        var result = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        return new EncryptionResult { Success = true, Output = result };
    }

    private EncryptionResult HashSm3(EncryptionRequest request)
    {
        var sm3 = new Org.BouncyCastle.Crypto.Digests.SM3Digest();
        var inputBytes = Encoding.UTF8.GetBytes(request.InputText);

        sm3.BlockUpdate(inputBytes, 0, inputBytes.Length);
        var hashBytes = new byte[sm3.GetDigestSize()];
        sm3.DoFinal(hashBytes, 0);

        var result = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        return new EncryptionResult { Success = true, Output = result };
    }

    private EncryptionResult EncryptSm4(EncryptionRequest request)
    {
        // Choose block cipher wrapper based on requested mode (CBC or ECB)
        // Default to CBC when unknown
        var engine = new SM4Engine();
        IBlockCipher blockCipher = request.Mode switch
        {
            CipherMode.ECB => engine, // ECB: use engine directly
            CipherMode.CBC => new CbcBlockCipher(engine),
            _ => new CbcBlockCipher(engine)
        };

        var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

        // 默认 SM4 密钥和 IV
        const string DefaultSm4Key = "sdscxxkjyxgs@com";
        const string DefaultSm4Iv = "~!@#$%^&*()~!@#$";

        //处理密钥
        var keyBytes = string.IsNullOrEmpty(request.Key)
 ? GetKeyBytes(DefaultSm4Key, 16)
 : GetKeyBytes(request.Key, 16);

        byte[] ivBytes = Array.Empty<byte>();

        if (request.Mode == CipherMode.ECB)
        {
            // ECB模式不使用IV
            cipher.Init(true, new KeyParameter(keyBytes));
        }
        else
        {
            // CBC（以及其他需要IV的模式）
            ivBytes = string.IsNullOrEmpty(request.IV)
            ? GetKeyBytes(DefaultSm4Iv, 16)
            : GetKeyBytes(request.IV, 16);

            cipher.Init(true, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));
        }

        var inputBytes = Encoding.UTF8.GetBytes(request.InputText);
        var output = new byte[cipher.GetOutputSize(inputBytes.Length)];
        var len = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, output, 0);
        cipher.DoFinal(output, len);

        var resultText = request.OutputBase64
        ? Convert.ToBase64String(output)
        : BitConverter.ToString(output).Replace("-", "");

        return new EncryptionResult { Success = true, Output = resultText, UsedKey = Convert.ToBase64String(keyBytes), UsedIV = ivBytes.Length > 0 ? Convert.ToBase64String(ivBytes) : string.Empty };
    }

    private EncryptionResult DecryptSm4(EncryptionRequest request)
    {
        // Support ECB and CBC
        var engine = new SM4Engine();
        IBlockCipher blockCipher = request.Mode switch
        {
            CipherMode.ECB => engine,
            CipherMode.CBC => new CbcBlockCipher(engine),
            _ => new CbcBlockCipher(engine)
        };

        var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

        // 获取 key/iv
        if (string.IsNullOrEmpty(request.Key) || (request.Mode != CipherMode.ECB && string.IsNullOrEmpty(request.IV)))
        {
            return new EncryptionResult { Success = false, ErrorMessage = "解密需要 Key 和 IV" };
        }

        var keyBytes = GetKeyBytes(request.Key, 16);
        byte[] ivBytes = Array.Empty<byte>();
        if (request.Mode != CipherMode.ECB)
        {
            ivBytes = GetKeyBytes(request.IV, 16);
            cipher.Init(false, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));
        }
        else
        {
            cipher.Init(false, new KeyParameter(keyBytes));
        }

        byte[] cipherBytes = request.OutputBase64 ? Convert.FromBase64String(request.InputText) : HexStringToBytes(request.InputText);
        var output = new byte[cipher.GetOutputSize(cipherBytes.Length)];
        var len = cipher.ProcessBytes(cipherBytes, 0, cipherBytes.Length, output, 0);
        cipher.DoFinal(output, len);

        var resultText = Encoding.UTF8.GetString(output).TrimEnd('\0');
        return new EncryptionResult { Success = true, Output = resultText };
    }

    private System.Security.Cryptography.CipherMode GetAesCipherMode(CipherMode mode)
    {
        return mode switch
        {
            CipherMode.CBC => System.Security.Cryptography.CipherMode.CBC,
            CipherMode.ECB => System.Security.Cryptography.CipherMode.ECB,
            CipherMode.CFB => System.Security.Cryptography.CipherMode.CFB,
            CipherMode.OFB => System.Security.Cryptography.CipherMode.OFB,
            _ => System.Security.Cryptography.CipherMode.CBC
        };
    }

    private byte[] GetKeyBytes(string key, int requiredLength)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (keyBytes.Length == requiredLength) return keyBytes;

        // 如果密钥长度不符，使用SHA256哈希并截取
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(keyBytes);
        var result = new byte[requiredLength];
        Array.Copy(hash, result, Math.Min(requiredLength, hash.Length));
        return result;
    }

    private byte[] GenerateRandomBytes(int length)
    {
        var bytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return bytes;
    }

    private static byte[] HexStringToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
        if (hex.Length % 2 == 1) throw new ArgumentException("Hex string must have even length");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}