using System;

namespace Natrium
{
    internal sealed class RandomNumberGenerator32 : IRandomNumberGenerator
    {
        public void GetRandomBytes(byte[] buffer)
        {
            PlatformInvoke32.randombytes_buf(buffer, new UIntPtr((uint)buffer.Length));
        }
    }
}
