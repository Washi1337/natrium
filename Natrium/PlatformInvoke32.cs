using System;
using System.Runtime.InteropServices;

namespace Natrium
{
    internal static class PlatformInvoke32
    {
        private const string LibraryName = "libsodium-32.dll";




        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sodium_init();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_publickeybytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_secretkeybytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_noncebytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_zerobytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_box_beforenmbytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box_beforenm(byte[] sharedSecret, byte[] publicKey, byte[] secretKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box_afternm(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] sharedSecret);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box_open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box_open_afternm(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] sharedSecret);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void randombytes_buf(byte[] buffer, UIntPtr size);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_sign_publickeybytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_sign_secretkeybytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr crypto_sign_bytes();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign(byte[] sig, ref long sigLength, byte[] message, long messageLength, byte[] secretKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_open(byte[] message, ref long messageLength, byte[] sig, long sigLength, byte[] publicKey);
    }
}
