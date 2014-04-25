using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Natrium
{
    /// <summary>
    /// Provides methods to encrypt and authenticate data using a public-key authenticator
    /// </summary>
    public interface IAuthenticatedPublicKeyCrypto
    {
        /// <summary>
        /// Gets the size, in bytes, of a nonce used in encryption
        /// </summary>
        uint NonceSize { get; }

        /// <summary>
        /// Creates a new random key pair
        /// </summary>
        /// <returns>The generated key pair</returns>
        PublicKeyCryptoKeyPair CreateRandomKeyPair();

        /// <summary>
        /// Creates a new random nonce
        /// </summary>
        /// <returns>The generated nonce</returns>
        byte[] CreateRandomNonce();

        /// <summary>
        /// Encrypts and authenticates a message
        /// </summary>
        /// <param name="message">The message to encrypt</param>
        /// <param name="nonce">An unique nonce value</param>
        /// <param name="key">Private key pair</param>
        /// <param name="recipientPublicKey">The public key of the recipient of the message</param>
        /// <returns>The encrypted message</returns>
        byte[] EncryptMessage(byte[] message, byte[] nonce, PublicKeyCryptoKeyPair key, PublicKeyCryptoPublicKey recipientPublicKey);

        /// <summary>
        /// Verifies and decrypts a message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message</param>
        /// <param name="nonce">The nonce value used to encrypt the message</param>
        /// <param name="key">Private key pair</param>
        /// <param name="senderPublicKey">The public key of the sender</param>
        /// <returns>The decrypted message</returns>
        /// <exception cref="CryptographicException">Thrown if integrity of the decrypted data cannot be confirmed</exception>
        byte[] VerifyAndDecryptMessage(byte[] encryptedMessage, byte[] nonce, PublicKeyCryptoKeyPair key, PublicKeyCryptoPublicKey senderPublicKey);

        /// <summary>
        /// Creates a multi-use crypter instance using the specified keys
        /// </summary>
        /// <param name="key">Private key pair</param>
        /// <param name="publicKey">The public key of the other side</param>
        /// <returns>A crypter context with the key parameters set</returns>
        IAuthenticatedPublicKeyCryptoContext CreateCrypterInstance(PublicKeyCryptoKeyPair key, PublicKeyCryptoPublicKey publicKey);
    }
}
