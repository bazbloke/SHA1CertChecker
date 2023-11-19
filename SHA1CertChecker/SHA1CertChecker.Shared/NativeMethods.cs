using System.Runtime.InteropServices;

namespace SHA1CertChecker.Shared
{
    public static class NativeMethods
    {
        public const int CTX_LENGTH = 0x960;

        [DllImport("sha1dcsum.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SHA1DCInit(ref SHA1_CTX ctx);

        [DllImport("sha1dcsum.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SHA1DCSetSafeHash(ref SHA1_CTX ctx, int safehash);

        [DllImport("sha1dcsum.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SHA1DCUpdate(ref SHA1_CTX ctx, byte[] buf, int len);

        [DllImport("sha1dcsum.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SHA1DCFinal(byte[] output, ref SHA1_CTX ctx);

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public unsafe struct SHA1_CTX
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = CTX_LENGTH)]
            public byte[] unnamed;

            public SHA1_CTX()
            {
                unnamed = new byte[CTX_LENGTH];
                for (int i = 0; i < unnamed.Length; i++)
                {
                    unnamed[i] = 0xcc; ;
                }
            }
        }
    }
}