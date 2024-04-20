using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Text;


var serviceCollection = new ServiceCollection();
serviceCollection.AddDataProtection()
    // point at a specific folder and use DPAPI to encrypt keys
    .PersistKeysToFileSystem(new DirectoryInfo(@"c:\temp-keys"));

var services = serviceCollection.BuildServiceProvider();

// perform a protect operation to force the system to put at least
// one key in the key ring
services.GetDataProtector("Sample.KeyManager.v1").Protect("payload");

// get a reference to the key manager
var dataProtectionProvider = services.GetService<IDataProtectionProvider>()!;
var dataProtection = dataProtectionProvider.CreateProtector("test");

// Ouvrir le fichier source
using (var sourceStream = File.OpenRead("plaintext.txt"))
// Créer un fichier de sortie chiffré
using (var encryptedFileStream = File.Create("encrypted.dat"))
// Créer un flux de chiffrement personnalisé
using (var encryptingStream = new CustomStream(encryptedFileStream, dataProtection, "mdp"))
{
    // Copier les données du fichier source vers le flux de chiffrement
    sourceStream.CopyTo(encryptingStream);
}

// Ouvrir le fichier chiffré
using (var encryptedFileStream = File.OpenRead("encrypted.dat"))
// Créer un fichier de sortie pour les données déchiffrées
using (var decryptedFileStream = File.Create("decrypted.txt"))
// Créer un flux de déchiffrement personnalisé
using (var decryptingStream = new CustomStream(encryptedFileStream, dataProtection, "mdp", true))
{
    // Copier les données du flux de déchiffrement vers le fichier de sortie
    decryptingStream.CopyTo(decryptedFileStream);
}


return;
public class CustomStream : Stream
{
    private readonly Stream _underlyingStream;
    private readonly IDataProtector _dataProtector;
    private readonly byte[] _encryptionKey;
    private readonly CryptoStream _cryptoStream;
    private readonly bool _isWriting;

    public CustomStream(Stream underlyingStream, IDataProtectionProvider dataProtectionProvider, string iv)
    {
        _underlyingStream = underlyingStream ?? throw new ArgumentNullException(nameof(underlyingStream));
        _dataProtector = dataProtectionProvider?.CreateProtector("CustomStreamEncryption") ?? throw new ArgumentNullException(nameof(dataProtectionProvider));

        var ivArray = Encoding.UTF8.GetBytes(iv);
        Array.Resize(ref ivArray, 16);

        Aes aes = Aes.Create();
        aes.GenerateKey();
        aes.IV = ivArray;
        _encryptionKey = aes.Key;

        // Chiffrer et stocker la clé dans le flux
        byte[] protectedKey = _dataProtector.Protect(_encryptionKey);

        if (protectedKey.Length != 132) throw new InvalidOperationException("La longeur du contenu protégé est invalide.");

        _underlyingStream.Write(protectedKey, 0, protectedKey.Length);
        _isWriting = true;

        // Créer un flux de chiffrement pour écrire les données chiffrées dans le flux sous-jacent
        _cryptoStream = new CryptoStream(_underlyingStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
    }

    public CustomStream(Stream underlyingStream, IDataProtectionProvider dataProtectionProvider, string iv, bool readKeyFromStream)
    {
        _underlyingStream = underlyingStream ?? throw new ArgumentNullException(nameof(underlyingStream));
        _dataProtector = dataProtectionProvider?.CreateProtector("CustomStreamEncryption") ?? throw new ArgumentNullException(nameof(dataProtectionProvider));

        if (readKeyFromStream)
        {
            // Lire la clé chiffrée depuis le flux
            byte[] encryptedKey = new byte[132]; // Taille de clé AES par défaut
            _underlyingStream.Read(encryptedKey, 0, encryptedKey.Length);

            // Déchiffrer la clé
            _encryptionKey = _dataProtector.Unprotect(encryptedKey);
            _isWriting = false;

            var ivArray = Encoding.UTF8.GetBytes(iv);
            Array.Resize(ref ivArray, 16);

            Aes aes = Aes.Create();
            aes.Key = _encryptionKey;
            aes.IV = ivArray;

            // Créer un flux de chiffrement pour lire et déchiffrer les données du flux sous-jacent
            _cryptoStream = new CryptoStream(_underlyingStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
        }
        else
        {
            throw new ArgumentException("CustomStream must be initialized with a key when readKeyFromStream is false.");
        }
    }

    public override bool CanRead => _underlyingStream.CanRead;

    public override bool CanSeek => _underlyingStream.CanSeek;

    public override bool CanWrite => _underlyingStream.CanWrite;

    public override long Length => _underlyingStream.Length;

    public override long Position
    {
        get => _underlyingStream.Position;
        set
        {
            _cryptoStream = new CryptoStream(_underlyingStream, _aes.CreateDecryptor(), CryptoStreamMode.Read);
            _underlyingStream.Position = value < 132 ? 132 : value; // On empêche de lire en bas de 132 puisque c'est notre clé qui est située là
        }
    }

    public override void Flush()
    {
        _cryptoStream.FlushFinalBlock();
        _underlyingStream.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return _cryptoStream.Read(buffer, offset, count);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return _underlyingStream.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        _underlyingStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (!_isWriting)
            throw new InvalidOperationException("Cannot write to the stream when initialized for reading only.");

        _cryptoStream.Write(buffer, offset, count);
    }

    private byte[] GenerateEncryptionKey(int size)
    {
        // Générer une clé aléatoire
        byte[] key = new byte[size]; // 256 bits
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }
        return key;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cryptoStream.Dispose();
            _underlyingStream.Dispose();
        }
        base.Dispose(disposing);
    }
}
