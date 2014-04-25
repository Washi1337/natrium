using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Natrium
{
    internal sealed class MessageSigner32 : IMessageSigner
    {
        private readonly uint _publicKeyBytes;
        private readonly uint _secretKeyBytes;
        private readonly uint _bytes;

        public MessageSigner32()
        {
            _publicKeyBytes = PlatformInvoke32.crypto_sign_publickeybytes().ToUInt32();
            _secretKeyBytes = PlatformInvoke32.crypto_sign_secretkeybytes().ToUInt32();
            _bytes = PlatformInvoke32.crypto_sign_bytes().ToUInt32();
        }

        public SignerKeyPair CreateRandomKeyPair()
        {
            var publicKey = new byte[_publicKeyBytes];
            var secretKey = new byte[_secretKeyBytes];
            var result = PlatformInvoke32.crypto_sign_keypair(publicKey, secretKey);

            if (result != 0) throw new CryptographicException("Failed");

            return new SignerKeyPair(secretKey, publicKey);
        }

        public byte[] SignMessage(byte[] message, SignerKeyPair key)
        {
            var signedMessage = new byte[message.Length + _bytes];
            long signedMessageRealLength = 0;

            var result = PlatformInvoke32.crypto_sign(signedMessage, ref signedMessageRealLength, message, message.Length,
                key.SecretKeyBytes);

            if (result != 0) throw new CryptographicException("Failed");

            Array.Resize(ref signedMessage, (int)signedMessageRealLength);
            return signedMessage;
        }

        public byte[] VerifySignedMessage(byte[] signedMessage, SignerPublicKey publicKey)
        {
            var message = new byte[signedMessage.Length];
            long messageRealLength = 0;

            var result = PlatformInvoke32.crypto_sign_open(message, ref messageRealLength, signedMessage, signedMessage.Length,
                publicKey.PlainBytes);

            if (result != 0) throw new CryptographicException("Failed");

            Array.Resize(ref message, (int)messageRealLength);
            return message;
        }
    }
}
