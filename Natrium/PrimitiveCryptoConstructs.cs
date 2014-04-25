using System;

namespace Natrium
{
    /// <summary>
    /// Provides access to various cryptographic constructs
    /// </summary>
    public class PrimitiveCryptoConstructs
    {
        // Singleton instance because sodium_init must be called once
        // Lazy-loading is utilized for all members

        private static readonly Lazy<PrimitiveCryptoConstructs> _instance = new Lazy<PrimitiveCryptoConstructs>(() => new PrimitiveCryptoConstructs());

        /// <summary>
        /// Gets the singleton instance of the class
        /// </summary>
        public static PrimitiveCryptoConstructs Instance
        {
            get { return _instance.Value; }
        }

        private PrimitiveCryptoConstructs()
        {
            if (Environment.Is64BitProcess)
            {
                PlatformInvoke64.sodium_init();
            }
            else
            {
                PlatformInvoke32.sodium_init();
            }
        }

        private readonly Lazy<IAuthenticatedPublicKeyCrypto> _authenticatedPublicKeyCrypto =
            new Lazy<IAuthenticatedPublicKeyCrypto>(() =>
            {
                if (Environment.Is64BitProcess)
                {
                    return new AuthenticatedPublicKeyCrypto64();
                }
                else
                {
                    return new AuthenticatedPublicKeyCrypto32();
                }
            });

        /// <summary>
        /// Gets an instance of a class for encrypting and decrypting messages using public-key cryptography
        /// </summary>
        public IAuthenticatedPublicKeyCrypto AuthenticatedPublicKeyCrypto
        {
            get { return _authenticatedPublicKeyCrypto.Value; }
        }

        private readonly Lazy<IMessageSigner> _messageSigner =
            new Lazy<IMessageSigner>(() =>
            {
                if (Environment.Is64BitProcess)
                {
                    return new MessageSigner64();
                }
                else
                {
                    return new MessageSigner32();
                }
            });

        /// <summary>
        /// Gets an instance of a class for digitally signing and verifying messages
        /// </summary>
        public IMessageSigner MessageSigner
        {
            get { return _messageSigner.Value; }
        }

        private readonly Lazy<IRandomNumberGenerator> _rng =
            new Lazy<IRandomNumberGenerator>(() =>
            {
                if (Environment.Is64BitProcess)
                {
                    return new RandomNumberGenerator64();
                }
                else
                {
                    return new RandomNumberGenerator32();
                }
            });

        /// <summary>
        /// Gets an instance of a cryptographically secure pseudo-random number generator (CSPRNG)
        /// </summary>
        public IRandomNumberGenerator Rng
        {
            get { return _rng.Value; }
        }


    }
}
