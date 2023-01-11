using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace LaRottaO.CSharp.Pbkdf2
{
    public class Pbkdf2
    {
        //Original code by Microsoft
        //Source https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing?view=aspnetcore-2.2

        public Tuple<String, String> generateHashAndSalt(String argClearTextToHash)
        {
            byte[] salt = new byte[128 / 8];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetNonZeroBytes(salt);
            }

            String saltResult = Convert.ToBase64String(salt);

            byte[] saltByteArray = Convert.FromBase64String(saltResult);

            string hashedResult = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: argClearTextToHash,
                salt: saltByteArray,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 65536,
                numBytesRequested: 512 / 8));

            return new Tuple<String, String>(hashedResult, saltResult);
        }

        public Boolean checkIfPasswordIsCorrect(String argStoredHash, String argStoredSalt, String argClearTextToCheck)
        {
            byte[] saltByteArray = Convert.FromBase64String(argStoredSalt);

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: argClearTextToCheck,
                salt: saltByteArray,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 65536,
                numBytesRequested: 512 / 8));

            return argStoredHash.Equals(hashed);
        }
    }
}