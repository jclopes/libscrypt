using System;
using System.Collections.Generic;
using System.Linq;

namespace libscrypt
{
    public static class SCrypt
    {
        public static byte[] SHA256(byte[] m)
        {
            UInt32[] hh = new UInt32[] {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };
            UInt32[] w = new UInt32[64];

            SHA256_blocks(m, w, hh);

            var bytesLeft = m.Length % 64;
            var bitLenHi = (m.Length / 0x20000000) | 0;
            var bitLenLo = m.Length << 3;
            var numZeros = (bytesLeft < 56) ? 56 : 120;
            List<byte> pl = new List<byte>(m.Skip(m.Length - bytesLeft));

            pl.Add(0x80);
            for (var i = bytesLeft + 1; i < numZeros; i++) { pl.Add(0); }
            pl.Add((byte)((bitLenHi >> 24) & 0xff));
            pl.Add((byte)((bitLenHi >> 16) & 0xff));
            pl.Add((byte)((bitLenHi >> 8) & 0xff));
            pl.Add((byte)((bitLenHi >> 0) & 0xff));
            pl.Add((byte)((bitLenLo >> 24) & 0xff));
            pl.Add((byte)((bitLenLo >> 16) & 0xff));
            pl.Add((byte)((bitLenLo >> 8) & 0xff));
            pl.Add((byte)((bitLenLo >> 0) & 0xff));

            SHA256_blocks(pl.ToArray(), w, hh);

            return new byte[32] {
                (byte)((hh[0] >> 24) & 0xff), (byte)((hh[0] >> 16) & 0xff), (byte)((hh[0] >> 8) & 0xff), (byte)((hh[0] >> 0) & 0xff),
                (byte)((hh[1] >> 24) & 0xff), (byte)((hh[1] >> 16) & 0xff), (byte)((hh[1] >> 8) & 0xff), (byte)((hh[1] >> 0) & 0xff),
                (byte)((hh[2] >> 24) & 0xff), (byte)((hh[2] >> 16) & 0xff), (byte)((hh[2] >> 8) & 0xff), (byte)((hh[2] >> 0) & 0xff),
                (byte)((hh[3] >> 24) & 0xff), (byte)((hh[3] >> 16) & 0xff), (byte)((hh[3] >> 8) & 0xff), (byte)((hh[3] >> 0) & 0xff),
                (byte)((hh[4] >> 24) & 0xff), (byte)((hh[4] >> 16) & 0xff), (byte)((hh[4] >> 8) & 0xff), (byte)((hh[4] >> 0) & 0xff),
                (byte)((hh[5] >> 24) & 0xff), (byte)((hh[5] >> 16) & 0xff), (byte)((hh[5] >> 8) & 0xff), (byte)((hh[5] >> 0) & 0xff),
                (byte)((hh[6] >> 24) & 0xff), (byte)((hh[6] >> 16) & 0xff), (byte)((hh[6] >> 8) & 0xff), (byte)((hh[6] >> 0) & 0xff),
                (byte)((hh[7] >> 24) & 0xff), (byte)((hh[7] >> 16) & 0xff), (byte)((hh[7] >> 8) & 0xff), (byte)((hh[7] >> 0) & 0xff)
            };
        }

        private static void SHA256_blocks(byte[] p, UInt32[] w, UInt32[] hh)
        {
            var K = new UInt32[64] {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
                0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
                0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
                0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
                0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };

            int off = 0;
            int len = p.Length;
            while (len >= 64)
            {
                UInt32 a = hh[0];
                UInt32 b = hh[1];
                UInt32 c = hh[2];
                UInt32 d = hh[3];
                UInt32 e = hh[4];
                UInt32 f = hh[5];
                UInt32 g = hh[6];
                UInt32 h = hh[7];
                UInt32 t1, t2;

                for (var i = 0; i < 16; i++)
                {
                    var j = off + i * 4;
                    w[i] = ((p[j] & (UInt32)0xff) << 24) | ((p[j + 1] & (UInt32)0xff) << 16) |
                        ((p[j + 2] & (UInt32)0xff) << 8) | (p[j + 3] & (UInt32)0xff);
                }

                for (var i = 16; i < 64; i++)
                {
                    UInt32 u = w[i - 2];
                    t1 = ((u >> 17) | (u << (32 - 17))) ^ ((u >> 19) | (u << (32 - 19))) ^ (u >> 10);

                    u = w[i - 15];
                    t2 = ((u >> 7) | (u << (32 - 7))) ^ ((u >> 18) | (u << (32 - 18))) ^ (u >> 3);

                    w[i] = (((t1 + w[i - 7]) | 0) + ((t2 + w[i - 16]) | 0)) | 0;
                }

                for (var i = 0; i < 64; i++)
                {
                    t1 = ((((((e >> 6) | (e << (32 - 6))) ^ ((e >> 11) | (e << (32 - 11))) ^
                             ((e >> 25) | (e << (32 - 25)))) + ((e & f) ^ (~e & g))) | 0) +
                          ((h + ((K[i] + w[i]) | 0)) | 0)) | 0;

                    t2 = ((((a >> 2) | (a << (32 - 2))) ^ ((a >> 13) | (a << (32 - 13))) ^
                           ((a >> 22) | (a << (32 - 22)))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;

                    h = g;
                    g = f;
                    f = e;
                    e = (d + t1) | 0;
                    d = c;
                    c = b;
                    b = a;
                    a = (t1 + t2) | 0;
                }

                hh[0] = (hh[0] + a) | 0;
                hh[1] = (hh[1] + b) | 0;
                hh[2] = (hh[2] + c) | 0;
                hh[3] = (hh[3] + d) | 0;
                hh[4] = (hh[4] + e) | 0;
                hh[5] = (hh[5] + f) | 0;
                hh[6] = (hh[6] + g) | 0;
                hh[7] = (hh[7] + h) | 0;

                off += 64;
                len -= 64;
            }
        }

        private delegate void incDelegate();

        public static byte[] PBKDF2_HMAC_SHA256_OneIter(byte[] password, byte[] salt, int dkLen)
        {
            // compress password if it's longer than hash block length
            password = password.Length <= 64 ? password : SHA256(password);

            var innerLen = 64 + salt.Length + 4;
            var inner = new byte[innerLen];
            var outerKey = new byte[64];
            List<byte> dk = new List<byte>();

            // inner = (password ^ ipad) || salt || counter
            for (var i = 0; i < 64; i++) inner[i] = 0x36;
            for (var i = 0; i < password.Length; i++) inner[i] ^= password[i];
            for (var i = 0; i < salt.Length; i++) inner[64 + i] = salt[i];
            for (var i = innerLen - 4; i < innerLen; i++) inner[i] = 0;

            // outerKey = password ^ opad
            for (var i = 0; i < 64; i++) outerKey[i] = 0x5c;
            for (var i = 0; i < password.Length; i++) outerKey[i] ^= password[i];

            // increments counter inside inner
            incDelegate incrementCounter = delegate
            {
                for (var i = innerLen - 1; i >= innerLen - 4; i--)
                {
                    inner[i]++;
                    if (inner[i] <= 0xff) return;
                    inner[i] = 0;
                }
            };

            // output blocks = SHA256(outerKey || SHA256(inner)) ...
            while (dkLen >= 32)
            {
                incrementCounter();
                var t = new List<byte>(outerKey);
                t.AddRange(SHA256(inner));
                dk.AddRange(SHA256(t.ToArray()));
                dkLen -= 32;
            }
            if (dkLen > 0)
            {
                incrementCounter();
                var t = new List<byte>(outerKey);
                t.AddRange(SHA256(inner));
                dk.AddRange(SHA256(t.ToArray()).Take(dkLen));
            }

            return dk.ToArray();
        }

        public static void blockmix_salsa8(UInt32[] BY, int Yi, int r, UInt32[] x, UInt32[] _X)
        {
            Array.ConstrainedCopy(BY, (2 * r - 1) * 16, _X, 0, 16);
            for (var i = 0; i < 2 * r; i++)
            {
                blockxor(BY, i * 16, _X, 16);
                salsa20_8(_X, x);
                Array.ConstrainedCopy(_X, 0, BY, Yi + (i * 16), 16);
            }

            for (var i = 0; i < r; i++)
            {
                Array.ConstrainedCopy(BY, Yi + (i * 2) * 16, BY, (i * 16), 16);
            }

            for (var i = 0; i < r; i++)
            {
                Array.ConstrainedCopy(BY, Yi + (i * 2 + 1) * 16, BY, (i + r) * 16, 16);
            }
        }

        private static void salsa20_8(UInt32[] B, UInt32[] x)
        {
            Array.ConstrainedCopy(B, 0, x, 0, 16);

            for (var i = 8; i > 0; i -= 2)
            {
                x[4] ^= R(x[0] + x[12], 7);
                x[8] ^= R(x[4] + x[0], 9);
                x[12] ^= R(x[8] + x[4], 13);
                x[0] ^= R(x[12] + x[8], 18);
                x[9] ^= R(x[5] + x[1], 7);
                x[13] ^= R(x[9] + x[5], 9);
                x[1] ^= R(x[13] + x[9], 13);
                x[5] ^= R(x[1] + x[13], 18);
                x[14] ^= R(x[10] + x[6], 7);
                x[2] ^= R(x[14] + x[10], 9);
                x[6] ^= R(x[2] + x[14], 13);
                x[10] ^= R(x[6] + x[2], 18);
                x[3] ^= R(x[15] + x[11], 7);
                x[7] ^= R(x[3] + x[15], 9);
                x[11] ^= R(x[7] + x[3], 13);
                x[15] ^= R(x[11] + x[7], 18);
                x[1] ^= R(x[0] + x[3], 7);
                x[2] ^= R(x[1] + x[0], 9);
                x[3] ^= R(x[2] + x[1], 13);
                x[0] ^= R(x[3] + x[2], 18);
                x[6] ^= R(x[5] + x[4], 7);
                x[7] ^= R(x[6] + x[5], 9);
                x[4] ^= R(x[7] + x[6], 13);
                x[5] ^= R(x[4] + x[7], 18);
                x[11] ^= R(x[10] + x[9], 7);
                x[8] ^= R(x[11] + x[10], 9);
                x[9] ^= R(x[8] + x[11], 13);
                x[10] ^= R(x[9] + x[8], 18);
                x[12] ^= R(x[15] + x[14], 7);
                x[13] ^= R(x[12] + x[15], 9);
                x[14] ^= R(x[13] + x[12], 13);
                x[15] ^= R(x[14] + x[13], 18);
            }

            for (var i = 0; i < 16; ++i)
            {
                B[i] += x[i];
            }
        }

        private static void blockxor(UInt32[] S, int Si, UInt32[] D, int len)
        {
            for (var i = 0; i < len; i++)
            {
                D[i] ^= S[Si + i];
            }
        }

        private static UInt32 R(UInt32 a, int b)
        {
            return (a << b) | (a >> (32 - b));
        }

        // N = Cpu cost, r = Memory cost, p = parallelization cost, dkLen = output key length
        public static byte[] scrypt(byte[] password, byte[] salt, int N, int r, int p, int dkLen)
        {
            var b = PBKDF2_HMAC_SHA256_OneIter(password, salt, p * 128 * r);
            var B = new UInt32[p * 32 * r];

            for (var i = 0; i < B.Length; i++)
            {
                var j = i * 4;
                B[i] = ((b[j + 3] & (UInt32)0xff) << 24) |
                       ((b[j + 2] & (UInt32)0xff) << 16) |
                       ((b[j + 1] & (UInt32)0xff) << 8) |
                       ((b[j + 0] & (UInt32)0xff) << 0);
            }

            var XY = new UInt32[64 * r];
            var V = new UInt32[32 * r * N];

            int Yi = 32 * r;

            // scratch space
            var x = new UInt32[16];       // salsa20_8
            var _X = new UInt32[16];      // blockmix_salsa8

            for (var ii = 0; ii < p; ii++)
            {
                int Bi = ii * 32 * r;

                Array.ConstrainedCopy(B, Bi, XY, 0, Yi);            // ROMix - 1

                for (var i = 0; i < N; i++)
                {                                                   // ROMix - 2
                    Array.ConstrainedCopy(XY, 0, V, i * Yi, Yi);    // ROMix - 3
                    blockmix_salsa8(XY, Yi, r, x, _X);              // ROMix - 4
                }

                for (var i = 0; i < N; i++)
                {                // ROMix - 6
                    var offset = (2 * r - 1) * 16;                  // ROMix - 7
                    var j = XY[offset] & ((UInt32)N - 1);
                    blockxor(V, (int)(j * Yi), XY, Yi);             // ROMix - 8 (inner)
                    blockmix_salsa8(XY, Yi, r, x, _X);              // ROMix - 9 (outer)
                }

                Array.ConstrainedCopy(XY, 0, B, Bi, Yi);            // ROMix - 10
            }
            var bb = new List<byte>();

            for (var i = 0; i < B.Length; i++)
            {
                bb.Add((byte)((B[i] >> 0) & 0xff));
                bb.Add((byte)((B[i] >> 8) & 0xff));
                bb.Add((byte)((B[i] >> 16) & 0xff));
                bb.Add((byte)((B[i] >> 24) & 0xff));
            }

            var derivedKey = PBKDF2_HMAC_SHA256_OneIter(password, bb.ToArray(), dkLen);

            return derivedKey;
        }
    }
}
