// Services/IEncryptionService.cs
using CrossPlatformCryptoTool.Models;
using System.Security.Cryptography;
using System.Text;

namespace CrossPlatformCryptoTool.Services;

public interface IEncryptionService
{
    EncryptionResult Encrypt(EncryptionRequest request);
    EncryptionResult Decrypt(EncryptionRequest request);
}