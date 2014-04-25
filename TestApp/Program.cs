using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Natrium;

namespace TestApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var signingKp = PrimitiveCryptoConstructs.Instance.MessageSigner.CreateRandomKeyPair();
            var publicKey = signingKp.PublicKey;

            var messageToSign = Encoding.UTF8.GetBytes("This string should not be tampered with");
            var signedMessage = PrimitiveCryptoConstructs.Instance.MessageSigner.SignMessage(messageToSign, signingKp);

            try
            {
                var confirmedMessage = PrimitiveCryptoConstructs.Instance.MessageSigner.VerifySignedMessage(signedMessage,
                    publicKey);

                Console.WriteLine("Verified message: " + Encoding.UTF8.GetString(confirmedMessage));
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Signature invalid!");
            }


            var aliceKeyPair = PrimitiveCryptoConstructs.Instance.AuthenticatedPublicKeyCrypto.CreateRandomKeyPair();
            var alicePublicKey = aliceKeyPair.PublicKey;

            var bobKeyPair = PrimitiveCryptoConstructs.Instance.AuthenticatedPublicKeyCrypto.CreateRandomKeyPair();
            var bobPublicKey = bobKeyPair.PublicKey;

            var c = PrimitiveCryptoConstructs.Instance.AuthenticatedPublicKeyCrypto.CreateCrypterInstance(aliceKeyPair,
                bobPublicKey);

            // define the message and nonce
            var nonce = PrimitiveCryptoConstructs.Instance.AuthenticatedPublicKeyCrypto.CreateRandomNonce();
            var message = Encoding.UTF8.GetBytes("This string should not be read by the NSA");

            // encrypt
            var encryptedMessage = c.Encrypt(message, nonce);

            // decrypt on Bob's side
            var decryptedMessage =
                PrimitiveCryptoConstructs.Instance.AuthenticatedPublicKeyCrypto.VerifyAndDecryptMessage(encryptedMessage,
                    nonce, bobKeyPair, alicePublicKey);

            Console.WriteLine("The message is: " + Encoding.UTF8.GetString(decryptedMessage));
            
            Console.ReadLine();
        }
    }
}
