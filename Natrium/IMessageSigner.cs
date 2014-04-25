using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Natrium
{
    /// <summary>
    /// Provides methods to digitally sign and verify messages
    /// </summary>
    public interface IMessageSigner
    {
        /// <summary>
        /// Creates a new random key pair
        /// </summary>
        /// <returns>The generated key pair</returns>
        SignerKeyPair CreateRandomKeyPair();

        /// <summary>
        /// Signs a message using the specified key pair
        /// </summary>
        /// <param name="message">The message to sign</param>
        /// <param name="key">The key pair to use</param>
        /// <returns>The signed message</returns>
        byte[] SignMessage(byte[] message, SignerKeyPair key);

        /// <summary>
        /// Verifies a signed message and returns the original message on success
        /// </summary>
        /// <param name="signedMessage">A signed message</param>
        /// <param name="publicKey">The public key to use for verification</param>
        /// <returns>The original message that was signed</returns>
        byte[] VerifySignedMessage(byte[] signedMessage, SignerPublicKey publicKey);
    }
}
