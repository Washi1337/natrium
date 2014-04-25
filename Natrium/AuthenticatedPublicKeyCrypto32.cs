using System;
using System.Security.Cryptography;

namespace Natrium
{
    internal sealed class AuthenticatedPublicKeyCrypto32 : IAuthenticatedPublicKeyCrypto
    {
        private readonly uint _publicKeyBytes;
        private readonly uint _secretKeyBytes;
        private readonly uint _zeroBytes;
        private readonly uint _beforeNmBytes;

        public AuthenticatedPublicKeyCrypto32()
        {
            _publicKeyBytes = PlatformInvoke32.crypto_box_publickeybytes().ToUInt32();
            _secretKeyBytes = PlatformInvoke32.crypto_box_secretkeybytes().ToUInt32();
            _zeroBytes = PlatformInvoke32.crypto_box_zerobytes().ToUInt32();
            _beforeNmBytes = PlatformInvoke32.crypto_box_beforenmbytes().ToUInt32();
            NonceSize = PlatformInvoke32.crypto_box_noncebytes().ToUInt32();
        }

        public uint NonceSize { get; private set; }

        public PublicKeyCryptoKeyPair CreateRandomKeyPair()
        {
            var publicKey = new byte[_publicKeyBytes];
            var secretKey = new byte[_secretKeyBytes];
            var result = PlatformInvoke32.crypto_box_keypair(publicKey, secretKey);

            if (result != 0) throw new CryptographicException("Failed");

            return new PublicKeyCryptoKeyPair(secretKey, publicKey);
        }

        public byte[] CreateRandomNonce()
        {
            var nonce = new byte[NonceSize];
            PlatformInvoke32.randombytes_buf(nonce, new UIntPtr((uint)nonce.Length));

            return nonce;
        }

        public byte[] EncryptMessage(byte[] message, byte[] nonce, PublicKeyCryptoKeyPair key, PublicKeyCryptoPublicKey recipientPublicKey)
        {
            // verify arguments
            if (nonce == null) throw new ArgumentNullException("nonce");
            if (nonce.Length != NonceSize)
                throw new ArgumentOutOfRangeException("nonce", string.Format("Nonce must be {0} bytes long", NonceSize));

            // pad the message (prepend zero bytes)
            var paddedMessage = new byte[_zeroBytes + message.Length];
            Buffer.BlockCopy(message, 0, paddedMessage, (int)_zeroBytes, message.Length);

            // encrypt
            var encryptedMessage = new byte[paddedMessage.Length];
            var result = PlatformInvoke32.crypto_box(encryptedMessage, paddedMessage, paddedMessage.Length, nonce, recipientPublicKey.PlainBytes,
                key.SecretKeyBytes);

            if (result != 0) throw new CryptographicException("Failed");

            return encryptedMessage;
        }

        public byte[] VerifyAndDecryptMessage(byte[] encryptedMessage, byte[] nonce, PublicKeyCryptoKeyPair key, PublicKeyCryptoPublicKey senderPublicKey)
        {
            // verify arguments
            if (nonce == null) throw new ArgumentNullException("nonce");
            if (nonce.Length != NonceSize)
                throw new ArgumentOutOfRangeException("nonce", string.Format("Nonce must be {0} bytes long", NonceSize));

            // decrypt
            var paddedMessage = new byte[encryptedMessage.Length];
            var result = PlatformInvoke32.crypto_box_open(paddedMessage, encryptedMessage, encryptedMessage.Length, nonce,
                senderPublicKey.PlainBytes, key.SecretKeyBytes);

            if (result != 0) throw new CryptographicException("Failed");

            var message = new byte[paddedMessage.Length - _zeroBytes];
            Buffer.BlockCopy(paddedMessage, (int)_zeroBytes, message, 0, message.Length);

            return message;
        }

        public IAuthenticatedPublicKeyCryptoContext CreateCrypterInstance(PublicKeyCryptoKeyPair key, PublicKeyCryptoPublicKey publicKey)
        {
            // compute the shared secret
            var sharedSecret = new byte[_beforeNmBytes];
            var result = PlatformInvoke32.crypto_box_beforenm(sharedSecret, publicKey.PlainBytes, key.SecretKeyBytes);

            if (result != 0) throw new CryptographicException("Failed");

            return new AuthenticatedPublicKeyCryptoContext(this, sharedSecret);
        }

        private class AuthenticatedPublicKeyCryptoContext : IAuthenticatedPublicKeyCryptoContext, IDisposable
        {
            private readonly AuthenticatedPublicKeyCrypto32 _parent;
            private readonly byte[] _sharedSecret;

            public AuthenticatedPublicKeyCryptoContext(AuthenticatedPublicKeyCrypto32 parent, byte[] sharedSecret)
            {
                _parent = parent;
                _sharedSecret = sharedSecret;
            }

            public void Dispose()
            {
                Array.Clear(_sharedSecret, 0, _sharedSecret.Length);
            }

            public byte[] Encrypt(byte[] message, byte[] nonce)
            {
                // verify arguments
                if (nonce == null) throw new ArgumentNullException("nonce");
                if (nonce.Length != _parent.NonceSize)
                    throw new ArgumentOutOfRangeException("nonce", string.Format("Nonce must be {0} bytes long", _parent.NonceSize));


                // pad the message (prepend zero bytes)
                var paddedMessage = new byte[_parent._zeroBytes + message.Length];
                Buffer.BlockCopy(message, 0, paddedMessage, (int)_parent._zeroBytes, message.Length);

                // encrypt
                var encryptedMessage = new byte[paddedMessage.Length];
                var result = PlatformInvoke32.crypto_box_afternm(encryptedMessage, paddedMessage, paddedMessage.Length, nonce, _sharedSecret);

                if (result != 0) throw new CryptographicException("Failed");

                return encryptedMessage;
            }

            public byte[] VerifyAndDecrypt(byte[] encryptedMessage, byte[] nonce)
            {
                // verify arguments
                if (nonce == null) throw new ArgumentNullException("nonce");
                if (nonce.Length != _parent.NonceSize)
                    throw new ArgumentOutOfRangeException("nonce", string.Format("Nonce must be {0} bytes long", _parent.NonceSize));


                // decrypt
                var paddedMessage = new byte[encryptedMessage.Length];
                var result = PlatformInvoke32.crypto_box_open_afternm(paddedMessage, encryptedMessage, encryptedMessage.Length, nonce, _sharedSecret);

                if (result != 0) throw new CryptographicException("Failed");

                var message = new byte[paddedMessage.Length - _parent._zeroBytes];
                Buffer.BlockCopy(paddedMessage, (int)_parent._zeroBytes, message, 0, message.Length);

                return message;
            }

        }
    }
}
