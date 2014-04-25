using System;

namespace Natrium
{
    internal sealed class RandomNumberGenerator64 : IRandomNumberGenerator
    {
        public void GetRandomBytes(byte[] buffer)
        {
            PlatformInvoke64.randombytes_buf(buffer, new UIntPtr((uint)buffer.Length));
        }
    }
}
