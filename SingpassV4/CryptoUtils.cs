using System;
using System.Security.Cryptography;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Jose;
using JWT.Builder;
using System.Collections.Generic;
using IdentityServer4.Models;
using Org.BouncyCastle.Crypto.Parameters;
using JWT.Algorithms;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using SingpassV4.Controllers;
using System.Security.Claims;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1.X9;




public static class CryptoUtils
{
	public static string GetContentsOfPem(string path)
	{
		try
		{
			//string pathToFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path + ".pem");
			if (File.Exists(path))
			{
				return File.ReadAllText(path);
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine(ex.Message);
		}

		return null;
	}
	public static (string PublicKey, string PrivateKey) GenerateECDsaKeyPair()
	{
		using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
		{
			// Export the public key
			string publicKey = ExportPublicKey(ecdsa);

			// Export the private key
			string privateKey = ExportPrivateKey(ecdsa);

			return (publicKey, privateKey);
		}
	}

	private static string ExportPublicKey(ECDsa ecdsa)
	{
		// Export parameters with only Q (public part)
		ECParameters parameters = ecdsa.ExportParameters(false);
		using (MemoryStream ms = new MemoryStream())
		{
			using (BinaryWriter writer = new BinaryWriter(ms))
			{
				writer.Write((byte)0x30); // SEQUENCE
				using (MemoryStream innerMs = new MemoryStream())
				{
					using (BinaryWriter innerWriter = new BinaryWriter(innerMs))
					{
						innerWriter.Write((byte)0x03); // BIT STRING
						innerWriter.Write((byte)0x42); // Length 66 bytes
						innerWriter.Write((byte)0x00); // Extra padding bit
						innerWriter.Write((byte)0x04); // Uncompressed indicator byte
						innerWriter.Write(parameters.Q.X);
						innerWriter.Write(parameters.Q.Y);

						writer.Write((byte)0x03); // BIT STRING
						writer.Write((byte)(innerMs.Length + 1)); // Length + 1 for unused bits
						writer.Write((byte)0x00); // Unused bits
						writer.Write(innerMs.ToArray());
					}
				}
				return Convert.ToBase64String(ms.ToArray());
			}
		}
	}

	private static string ExportPrivateKey(ECDsa ecdsa)
	{
		// Export parameters including D (private part)
		ECParameters parameters = ecdsa.ExportParameters(true);
		using (MemoryStream ms = new MemoryStream())
		{
			using (BinaryWriter writer = new BinaryWriter(ms))
			{
				writer.Write((byte)0x30); // SEQUENCE
				using (MemoryStream innerMs = new MemoryStream())
				{
					using (BinaryWriter innerWriter = new BinaryWriter(innerMs))
					{
						innerWriter.Write((byte)0x04); // OCTET STRING
						innerWriter.Write((byte)parameters.D.Length);
						innerWriter.Write(parameters.D);

						writer.Write((byte)0x04); // OCTET STRING
						writer.Write((byte)(innerMs.Length));
						writer.Write(innerMs.ToArray());
					}
				}
				return Convert.ToBase64String(ms.ToArray());
			}
		}
	}

	//Crypto Utility
	public static async Task<EphemeralKeyPair> GenerateEphemeralKey()
	{
		EphemeralKeyPair keyPair = new EphemeralKeyPair();

		using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
		{
			// Export public key in PEM format
			keyPair.publicKey = ecdsa.ExportSubjectPublicKeyInfo().ToPemString("public");

			// Export private key in PEM format
			keyPair.privateKey = ecdsa.ExportPkcs8PrivateKey().ToPemString("private");
		}

		return keyPair;
	}


	private static string Base64UrlEncode(byte[] bytes)
	{
		return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
	}
	public static string ToPemString(this byte[] key, string type)
	{
		var base64 = Convert.ToBase64String(key);
		var pem = new StringBuilder();
		if(type == "private")
		{
			pem.AppendLine("-----BEGIN PRIVATE KEY-----");
			pem.AppendLine(base64);
			pem.AppendLine("-----END PRIVATE KEY-----");
		}
		else
		{
			pem.AppendLine("-----BEGIN PUBLIC KEY-----");
			pem.AppendLine(base64);
			pem.AppendLine("-----END PUBLIC KEY-----");
		}
		
		return pem.ToString();
	}
	
	//JWT Generator
	public class JwtHeader
	{
		public string typ { get; set; }
		public Dictionary<string, string> jwk { get; set; }
	}

	public class JwtClaims
	{
		public string htu { get; set; }
		public string htm { get; set; }
		public string jti { get; set; }
		public int iat { get; set; }
		public int exp { get; set; }
		public string ath { get; set; }
	}
	
	//public static string GenerateClientAssertion(string url, string clientID, string privateSigningKey)
	//{
	//	try
	//	{
	//		long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

	//		// Generate JWT token descriptor
	//		var tokenDescriptor = new SecurityTokenDescriptor
	//		{
	//			Subject = new System.Security.Claims.ClaimsIdentity(new[]
	//			{
	//				new System.Security.Claims.Claim("iss", clientID),
	//				new System.Security.Claims.Claim("sub", clientID),
	//				new System.Security.Claims.Claim("aud", url),
	//			}),
	//			Expires = DateTime.UtcNow.AddMinutes(5),
	//			IssuedAt = DateTime.UtcNow,
	//			SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(privateSigningKey)), SecurityAlgorithms.HmacSha256Signature)
	//		};

	//		// Create JWT token handler
	//		var tokenHandler = new JwtSecurityTokenHandler();

	//		// Generate JWT token
	//		var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

	//		// Write JWT token as string
	//		return tokenHandler.WriteToken(token);
	//	}
	//	catch (Exception ex)
	//	{
	//		Console.WriteLine(ex.Message);
	//	}
	//	return "";
	//}

	public static string GenerateClientAssertion(string url, string clientId, string privateSigningKey, string jktThumbprint)
	{
		long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

		var payload = new
		{
			sub = clientId,
			jti = Guid.NewGuid().ToString(),
			aud = url,
			iss = clientId,
			iat = now,
			exp = now + 300,
			cnf = new
			{
				jkt = jktThumbprint
			}
		};

		using ECDsa ecdsa = ECDsa.Create();
		ecdsa.ImportFromPem(privateSigningKey);

		var jwtHandler = new JwtSecurityTokenHandler();
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity(),
			Issuer = clientId,
			Audience = url,
			Expires = payload.exp == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(payload.exp).DateTime,
			IssuedAt = payload.iat == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(payload.iat).DateTime,
			NotBefore = payload.iat == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(payload.iat).DateTime,
			SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(ecdsa), Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256)
		};
		var jwtToken = jwtHandler.CreateToken(tokenDescriptor);

		return jwtHandler.WriteToken(jwtToken);
	}

	public static void ImportFromPemE(this ECDsa ecdsa, string pemString)
	{
		var ecdsaParams = GetECDSAParametersFromPem(pemString);
		ecdsa.ImportParameters(ecdsaParams);
	}

	public static ECParameters GetECDSAParametersFromPem(string pemString)
	{
		// Remove PEM header and footer
		pemString = Regex.Replace(pemString, @"-----(BEGIN|END) PRIVATE KEY-----", "", RegexOptions.Multiline).Trim();

		// Decode Base64 PEM content
		byte[] keyBytes = Convert.FromBase64String(pemString);

		// Parse DER encoded data
		using (var reader = new System.IO.BinaryReader(new System.IO.MemoryStream(keyBytes)))
		{
			if (reader.ReadByte() != 0x30) // SEQUENCE
				throw new ArgumentException("Invalid ECDSA key format.");

			int length = ReadLength(reader);

			byte[] r = reader.ReadBytes(length);

			byte[] s = reader.ReadBytes(length);

			int oidLength = ReadLength(reader);
			byte[] oidBytes = reader.ReadBytes(oidLength);

			// Get curve OID
			string oidString = BitConverter.ToString(oidBytes).Replace("-", "");
			ECCurve curve = GetCurveFromOid(oidString);

			// Populate ECParameters
			ECParameters ecParams = new ECParameters
			{
				Curve = curve,
				Q = new ECPoint { X = r, Y = s }
			};

			return ecParams;
		}
	}

	private static ECCurve GetCurveFromOid(string oidString)
	{
		switch (oidString)
		{
			case "6EC98BBF07091D9E19B5F91E5C02AF1376F0D95100D6FE68FADA":
				return ECCurve.NamedCurves.nistP256; 
			default:
				throw new ArgumentException("Unsupported ECDSA curve OID: " + oidString);
		}
	}
	private static int ReadLength(System.IO.BinaryReader reader)
	{
		byte b = reader.ReadByte();
		if (b == 0x81)
		{
			return reader.ReadByte();
		}
		else if (b == 0x82)
		{
			byte b1 = reader.ReadByte();
			byte b2 = reader.ReadByte();
			return (ushort)(b1 << 8 | b2);
		}
		return b;
	}

	//public async static Task<string> GenerateDpop(string url, string method, string privateKey, ECDsa ecPublicKey, string auth)
	//{
	//	var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
	//	var jwkFinal = ecPublicKey.ExportParameters(false);
	//	var thumbprint = GeneratePublicJwkThumbprint(jwkFinal);

	//	var header = new JwtHeader
	//	{
	//		typ = "dpop+jwt",
	//		jwk = new Dictionary<string, string>
	//		{
	//			{ "kty", "EC" },
	//			{ "crv", "P-256" },
	//			{ "x", Base64UrlEncoder.Encode(jwkFinal.Q.X) },
	//			{ "y", Base64UrlEncoder.Encode(jwkFinal.Q.Y) },
	//			{ "kid", thumbprint },
	//			{ "use", "sig" },
	//			{ "alg", "ES256" }
	//		}
	//	};
	//	var headerJson = JsonConvert.SerializeObject(header);
	//	var claims = new JwtClaims
	//	{
	//		htu = url,
	//		htm = method,
	//		jti = GenerateRandomString(40),
	//		iat = (int)now,
	//		exp = (int)(now + 120),
	//		ath = auth
	//	};

	//	var token = Jose.JWT.Encode(claims, privateKey, JwsAlgorithm.ES256, extraHeaders: JsonConvert.DeserializeObject<Dictionary<string, object>>(headerJson));
	//	return token;
	//}

	//public static async Task<string> GenerateDPoP(string url, string ath, string method, EphemeralKeyPair ephemeralKeyPair)
	//{
	//	try
	//	{
	//		long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

	//		var payload = new
	//		{
	//			htu = url,
	//			htm = method,
	//			jti = GenerateRandomString(40),
	//			iat = now,
	//			exp = now + 120,
	//			ath = !string.IsNullOrEmpty(ath) ? ath : null
	//		};


	//		using (ECDsa privateKey = ECDsa.Create())
	//		{
	//			// Decode Base64 PEM content
	//			byte[] keyBytes = Convert.FromBase64String(ephemeralKeyPair.privateKey);



	//			// Import the EC private key
	//			privateKey.ImportParameters(ecParams);

	//			var jwk = JObject.Parse(ephemeralKeyPair.publicKey);
	//			jwk["use"] = "sig";
	//			jwk["alg"] = "ES256";

	//			var header = new Dictionary<string, object>
	//		{
	//			{ "typ", "dpop+jwt" },
	//			{ "jwk", jwk }
	//		};

	//			var tokenHandler = new JwtSecurityTokenHandler();
	//			var tokenDescriptor = new SecurityTokenDescriptor
	//			{
	//				Subject = new ClaimsIdentity(),
	//				IssuedAt = payload.iat == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(payload.iat).DateTime,
	//				Expires = payload.exp == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(payload.exp).DateTime,
	//				SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(privateKey), SecurityAlgorithms.EcdsaSha256)
	//			};
	//			tokenDescriptor.AdditionalHeaderClaims = header;

	//			var jwtToken = tokenHandler.CreateToken(tokenDescriptor);
	//			var dpop = tokenHandler.WriteToken(jwtToken);

	//			return dpop;
	//		}
	//	}
	//	catch (Exception ex)
	//	{

	//		throw ex;
	//	}

	//}


	public async static Task<string> GenerateDpopProof(string url, string method, EphemeralKeyPair ephemeralKeyPair, string ath = null)
	{
		try
		{
			long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			var payload =  new Dictionary<string, object>
			{
				{ "htu", url },
				{ "htm", method },
				{ "jti", GenerateRandomString(40) },
				{ "iat", now },
				{ "exp", now + 120 },
			};

			if (!ath.IsNullOrEmpty())
			{
				payload.Add("ath", ath);
			}
			using (ECDsa privateKey = ECDsa.Create())
			{
				privateKey.ImportFromPem(ephemeralKeyPair.privateKey);

				var jwk = new Dictionary<string, object>
				{
					{ "kty", "EC" }, // Key Type
					{ "kid", "CRx5jixF8ZLRpxpqguxCwiq0g6b-ACHfQQJT7uiAkio" }, // Key ID ????
					{ "crv", "P-256" }, // Curve
					{ "x", "mxVK8wvCaQ8iUJ4AyZr1oK1_ceL_27kgTPISNEcChm4" }, // X Coordinate ???
					{ "y", "0P-81zpWvcy6YAPSiV_K4h94wdEdk-RwrhbTL0fkeyc" }, // Y Coordinate ???
					{ "use", "sig" }, // Use
					{ "alg", "ES256" } // Algorithm
				};

				var header = new Dictionary<string, object>
				{
					{ "typ", "dpop+jwt" },
					{ "jwk", jwk }
				};

				var jwtToken = Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256, extraHeaders: header);
				return jwtToken;
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("generateDpopProof error: " + ex.Message);
			throw;
		}
	}

	public class EphemeralKeyPair
	{
		public string privateKey { get; set; }
		public string publicKey { get; set; }
	}
	private static string GenerateRandomString(int length)
	{
		const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		var random = new Random();
		return new string(Enumerable.Repeat(chars, length)
		  .Select(s => s[random.Next(s.Length)]).ToArray());
	}

	private static string GeneratePublicJwkThumbprint(ECParameters jwkFinal)
	{
		using (var ecdsa = ECDsa.Create(jwkFinal))
		{
			var thumbprint = ecdsa.ExportSubjectPublicKeyInfo();
			return Base64UrlEncoder.Encode(thumbprint);
		}
	}

}


