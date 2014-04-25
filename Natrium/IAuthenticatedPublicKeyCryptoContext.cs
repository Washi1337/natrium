using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Natrium
{
    public interface IAuthenticatedPublicKeyCryptoContext
    {
        /// <summary>
        /// Encrypts and authenticates a message
        /// </summary>
        /// <param name="message">The message to encrypt</param>
        /// <param name="nonce">An unique nonce value</param>
        /// <returns>The encrypted message</returns>
        byte[] Encrypt(byte[] message, byte[] nonce);

        /// <summary>
        /// Verifies and decrypts a message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message</param>
        /// <param name="nonce">The nonce value used to encrypt the message</param>
        /// <returns>The decrypted message</returns>
        /// <exception cref="CryptographicException">Thrown if integrity of the decrypted data cannot be confirmed</exception>
        byte[] VerifyAndDecrypt(byte[] encryptedMessage, byte[] nonce);
    }
}
