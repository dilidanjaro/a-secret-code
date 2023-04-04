using System;
using System.Security.Cryptography;

namespace OneTimePasswordGenerator {
    public class OTPGenerator {
        private const int PASSWORD_LENGTH = 6;
        private const int VALIDITY_PERIOD = 30;

        public static string GenerateOTP(string userId, DateTime dateTime, string secretKey) {
            // Convert the Unix time to a byte array
            TimeSpan timeSpan = dateTime - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long unixTime = (long)timeSpan.TotalSeconds;
            byte[] unixTimeBytes = BitConverter.GetBytes(unixTime);

            // Concatenate the user ID and Unix time byte arrays and compute the HOTP value
            byte[] message = new byte[userId.Length + unixTimeBytes.Length];
            System.Buffer.BlockCopy(userId.ToCharArray(), 0, message, 0, userId.Length);
            System.Buffer.BlockCopy(unixTimeBytes, 0, message, userId.Length, unixTimeBytes.Length);
            byte[] hotpValue = ComputeHOTP(message, secretKey, VALIDITY_PERIOD);

            // Extract the one-time password digits from the HOTP value and return them as a string
            int startIndex = hotpValue[19] & 0xF;
            int otpValue = ((hotpValue[startIndex] & 0x7F) << 24) |
                           ((hotpValue[startIndex + 1] & 0xFF) << 16) |
                           ((hotpValue[startIndex + 2] & 0xFF) << 8) |
                           (hotpValue[startIndex + 3] & 0xFF);
            otpValue %= (int)Math.Pow(10, PASSWORD_LENGTH);
            return otpValue.ToString().PadLeft(PASSWORD_LENGTH, '0');
        }

        private static byte[] ComputeHOTP(byte[] message, string secretKey, int validityPeriod) {
            byte[] keyBytes = Base32Encoding.ToBytes(secretKey);
            HMACSHA1 hmacSha1 = new HMACSHA1(keyBytes);

            byte[] counterBytes = new byte[8];
            long counter = (DateTime.UtcNow.Ticks / TimeSpan.TicksPerSecond) / validityPeriod;
            for (int i = 7; i >= 0; i--) {
                counterBytes[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            byte[] hash = hmacSha1.ComputeHash(counterBytes);
            return hash;
        }
    }

    public static class Base32Encoding {
        private const string BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static byte[] ToBytes(string base32String) {
            byte[] bytes = new byte[base32String.Length * 5 / 8];
            int bitsRemaining = 0;
            int bitsNeeded = 8;
            int byteIndex = 0;
            char nextChar;

            foreach (char c in base32String) {
                int charValue = BASE32_ALPHABET.IndexOf(c);

                if (bitsRemaining <= bitsNeeded) {
                    byteIndex++;
                    bitsRemaining = 8;
                }

                bytes[byteIndex - 1] |= (byte)(charValue << (bitsRemaining - bitsNeeded));
                bitsRemaining -= bitsNeeded;
                bitsNeeded = 5;
            }

            return bytes;
        }
    }
}
