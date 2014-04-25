using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Natrium
{
    /// <summary>
    /// Provides a cryptographically secure random number generator
    /// </summary>
    public interface IRandomNumberGenerator
    {
        /// <summary>
        /// Fills a buffer with cryptographically secure random bytes
        /// </summary>
        /// <param name="buffer">The buffer to fill</param>
        void GetRandomBytes(byte[] buffer);
    }
}
