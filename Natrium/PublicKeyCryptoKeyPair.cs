using System;

namespace Natrium
{
    /// <summary>
    /// Represents a key pair used for authenticated public-key encryption
    /// </summary>
    public sealed class PublicKeyCryptoKeyPair : IDisposable
    {
        private readonly byte[] _secretKeyBytes;
        private readonly PublicKeyCryptoPublicKey _publicKey;

        public PublicKeyCryptoKeyPair(byte[] secretKeyBytes, byte[] publicKey)
        {
            _secretKeyBytes = secretKeyBytes;
            _publicKey = new PublicKeyCryptoPublicKey(publicKey);
        }

        public void Dispose()
        {
            if (_secretKeyBytes != null) Array.Clear(_secretKeyBytes, 0, _secretKeyBytes.Length);
            _publicKey.Dispose();
        }

        /// <summary>
        /// The secret key part of the keypair
        /// </summary>
        public byte[] SecretKeyBytes
        {
            get { return _secretKeyBytes; }
        }

        /// <summary>
        /// The public key part of the keypair
        /// </summary>
        public PublicKeyCryptoPublicKey PublicKey
        {
            get { return _publicKey; }
        }
    }

    /// <summary>
    /// Represents a public key used for authenticated public-key encryption
    /// </summary>
    public sealed class PublicKeyCryptoPublicKey : IDisposable
    {
        private readonly byte[] _keyBytes;

        public PublicKeyCryptoPublicKey(byte[] keyBytes)
        {
            _keyBytes = keyBytes;
        }

        /// <summary>
        /// Gets the public-key bytes
        /// </summary>
        public byte[] PlainBytes
        {
            get { return _keyBytes; }
        }

        public void Dispose()
        {
            if (_keyBytes != null) Array.Clear(_keyBytes, 0, _keyBytes.Length);
        }
    }
}
