using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace TwoFactorAuthentication.Helpers {
	public static class Hashing {

		/// <summary>
		/// Method will salt and hash a password given an input string containing said password.
		/// </summary>
		/// <param name="value"></param>
		/// <returns>array of byte arrays consisting of hashed password and the salt used in hashing.</returns>
		public static byte[][] GenerateHash(string value){
			byte[] salt = GetSalt();
			return new byte[][] { Hash(Encoding.UTF8.GetBytes(value), salt), salt };
		}

		/// <summary>
		/// Overload method for specifing a predetermined salt as a Guid.
		/// </summary>
		/// <param name="value">password/value to hash</param>
		/// <param name="salt">salt used in hashing algorithm</param>
		/// <returns>array of byte arrays containing hashed value and salt respectively.</returns>
		public static byte[][] GenerateHash(string value, Guid salt) {
			byte[] saltBytes = salt.ToByteArray();
			return new byte[][] { Hash(Encoding.UTF8.GetBytes(value), saltBytes), saltBytes };
		}

		/// <summary>
		/// Hashes together two byte arrays consisting of a value and salt.
		/// </summary>
		/// <param name="value">password converted to byte array.</param>
		/// <param name="salt">salt as byte array</param>
		/// <returns>byte array of hashed password + salt</returns>
		private static byte[] Hash(byte[] value, byte[] salt) {
			byte[] saltedValue = value.Concat(salt).ToArray();
			return new SHA256Managed().ComputeHash(saltedValue);
		}

		/// <summary>
		/// Uses the recommended cryptographic RNG generator to create a unique salt.
		/// </summary>
		/// <param name="length">The length we want out salt to be, 16 bytes by default.</param>
		/// <returns>byte[] containing the randomly generated salt</returns>
		private static byte[] GetSalt(int length = 16) {
			var salt = new byte[length];
			using (var random = new RNGCryptoServiceProvider()) {
				random.GetNonZeroBytes(salt);
			}
			return salt;
		}
	}
}