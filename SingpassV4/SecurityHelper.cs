
using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using Jose;



public static class SecurityHelper
{
	public static async Task<string> GenerateJwkThumbprint(string jwk)
	{
		try
		{
			byte[] jwkBytes = Encoding.UTF8.GetBytes(jwk);
			byte[] jwkThumbprintBuffer;

			using (SHA256 sha256 = SHA256.Create())
			{
				jwkThumbprintBuffer = sha256.ComputeHash(jwkBytes);
			}

			string jwkThumbprint = Base64UrlEncode(jwkThumbprintBuffer);

			return jwkThumbprint;
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error generating JWK thumbprint: " + ex.Message);
			throw;
		}
	}


	public static async Task<object> VerifyJWS(string compactJWS, string jwksUrl)
	{
		try
		{
			string rsaPublicKey = await GetRsaPublicKey(jwksUrl);
			var rsa = RSA.Create();

			// Import the RSA public key
			rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(rsaPublicKey), out _);

			var tokenHandler = new JwtSecurityTokenHandler();
			var validationParameters = new TokenValidationParameters
			{
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new RsaSecurityKey(rsa)
			};

			ClaimsPrincipal validatedPrincipal;
			try
			{
				// Validate the token and get the ClaimsPrincipal
				validatedPrincipal = tokenHandler.ValidateToken(compactJWS, validationParameters, out _);
			}
			catch (Exception ex)
			{
				throw new Exception("Error validating token", ex);
			}

			// Extract the JwtSecurityToken from the ClaimsPrincipal
			var jwtToken = validatedPrincipal.FindFirst("JwtSecurityToken").Value;

			// Check if the JwtSecurityToken is empty
			if (!string.IsNullOrEmpty(jwtToken))
			{
				return jwtToken;
			}
			else
			{
				throw new Exception("Invalid token type");
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error with verifying JWS: " + ex.Message);
			throw new Exception("Error verifying JWS", ex);
		}
	}

	private static async Task<string> GetRsaPublicKey(string jwksUrl)
	{
		try
		{
			using (HttpClient client = new HttpClient())
			{
				HttpResponseMessage response = await client.GetAsync(jwksUrl);
				response.EnsureSuccessStatusCode(); // Throw on error code
				string jwksJson = await response.Content.ReadAsStringAsync();
				var jwks = JObject.Parse(jwksJson);
				string rsaPublicKey = jwks["keys"][0]["publicKey"].ToString(); // Assuming JWKS JSON contains RSA public key
				return rsaPublicKey;
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error retrieving RSA public key: " + ex.Message);
			throw new Exception("Error retrieving RSA public key");
		}
	}

	public static async Task<string> DecryptJWEWithKey(string compactJWE, string decryptionPrivateKey)
	{

		try
		{
			string[] jweParts = compactJWE.Split('.'); // header.encryptedKey.iv.ciphertext.tag
			if (jweParts.Length != 5)
			{
				throw new ArgumentException("Invalid JWE data");
			}

			byte[] encryptedKey = Convert.FromBase64String(jweParts[1]);
			byte[] iv = Convert.FromBase64String(jweParts[2]);
			byte[] cipherText = Convert.FromBase64String(jweParts[3]);
			byte[] tag = Convert.FromBase64String(jweParts[4]);

			using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
			{
				rsa.FromXmlString(decryptionPrivateKey); // Load the RSA private key

				byte[] decryptedKey = rsa.Decrypt(encryptedKey, false);

				using (Aes aes = Aes.Create())
				{
					aes.Key = decryptedKey;
					aes.IV = iv;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.PKCS7;

					using (ICryptoTransform decryptor = aes.CreateDecryptor())
					{
						byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
						return Encoding.UTF8.GetString(decryptedBytes);
					}
				}
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error decrypting JWE: " + ex.Message);
			throw;
		}
	}

	public static async Task<string> GenerateDpop(string url, string ath, string method, string privateSigningKey)
	{
		try
		{
			var now = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();
			var payload = new JwtPayload
			{
				{"htu", url},
				{"htm", method},
				{"jti", GenerateRandomString(40)},  
                {"iat", now},
				{"exp", now + 120}  // Token expiry time (2 minutes from creation)
            };

			if (!string.IsNullOrEmpty(ath))
				payload["ath"] = ath;
			var sessionEphemeralPrivateKeyEDCsa = ConvertToECDsa(privateSigningKey);
			var header = new JwtHeader(new SigningCredentials(
				new ECDsaSecurityKey(sessionEphemeralPrivateKeyEDCsa) { KeyId = "dpop+jwt" },
				SecurityAlgorithms.EcdsaSha256))
			{
				{"typ", "dpop+jwt"},
				{"alg", "ES256"},
				{"jwk", new JsonWebKey { Kty = "EC", Use = "sig", Alg = "ES256" }}
			};

			var token = new JwtSecurityToken(header, payload);
			var tokenHandler = new JwtSecurityTokenHandler();
			return tokenHandler.WriteToken(token);
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error in GenerateDpop: " + ex.Message);
			throw;
		}
	}


	public static async Task<string> GenerateClientAssertion(string url, string clientId, string privateSigningKey, string jktThumbprint, string kid)
	{
		try
		{
			long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

			var payload = new
			{
				sub = clientId,
				jti = GenerateRandomString(40),
				aud = url,
				iss = clientId,
				iat = now,
				exp = now + 300,
				cnf = new
				{
					jkt = jktThumbprint
				}
			};

			// Extract base64 private key
			const string beginMarker = "-----BEGIN EC PRIVATE KEY-----";
			const string endMarker = "-----END EC PRIVATE KEY-----";
			int beginIndex = privateSigningKey.IndexOf(beginMarker) + beginMarker.Length;
			int endIndex = privateSigningKey.IndexOf(endMarker, beginIndex);
			if (beginIndex == -1 || endIndex == -1)
			{
				throw new ArgumentException("Invalid private key format");
			}
			string base64PrivateKey = privateSigningKey.Substring(beginIndex, endIndex - beginIndex).Trim();
			var privateKeyList = base64PrivateKey.Split('\r');

			string privateKeyBuild = "";
			for (int i = 0; i < privateKeyList.Length; i++)
			{
				privateKeyBuild+=privateKeyList[i].Replace("\n", "");
			}

			// Convert base64 string to bytes
			byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBuild);

			//using (RSA rsa = LoadRsaPrivateKey(privateSigningKey))
			//{
			//	// Encode JWT
			//	var jwtToken = Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
			//	return jwtToken;
			//}
			using (ECDsa ecdsa = LoadECDsaPrivateKey(privateKeyBuild))
			{
				// Encode JWT
				var jwtToken = Jose.JWT.Encode(payload, ecdsa, Jose.JwsAlgorithm.ES256);
				return jwtToken;
			}

		}
		catch (Exception ex)
		{
			Console.WriteLine("Error generating client assertion: " + ex.Message);
			throw;
		}
	}

	public static async Task<string> GenerateClientAssertion2(string url, string clientId, string jktThumbprint, string keyId, ECParameters ecParameters)
	{
		// Prepare the JWT payload
		var payload = new
		{
			iss = clientId,
			sub = clientId,
			aud = url,
			exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
			iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
			jti = Guid.NewGuid().ToString(),
		};

		// Convert EC private key parameters to CngKey
		CngKey cngKey;
		using (ECDsa ecdsa = ECDsa.Create())
		{
			ecdsa.ImportParameters(ecParameters);
			cngKey = CngKey.Import(ecdsa.ExportParameters(true).D, CngKeyBlobFormat.EccPrivateBlob);
		}

		// Sign the JWT with the EC private key
		string jwt;
		using (ECDsaCng signingKey = new ECDsaCng(cngKey))
		{
			jwt = Jose.JWT.Encode(payload, signingKey, JwsAlgorithm.ES256);
		}

		return jwt;
	}
	private static RSA LoadRsaPrivateKey(string privateKey)
	{
		using (TextReader privateKeyReader = new StringReader(privateKey))
		{
			PemReader pemReader = new PemReader(privateKeyReader);
			AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
			RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);
			RSA rsa = RSA.Create();
			rsa.ImportParameters(rsaParameters);
			return rsa;
		}
	}
	private static ECDsa LoadECDsaPrivateKey(string privateKey)
	{
		using (TextReader privateKeyReader = new StringReader(privateKey))
		{
			PemReader pemReader = new PemReader(privateKeyReader);
			AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
			ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters)keyPair.Private;

			var domainParams = privateKeyParams.Parameters;
			var curve = domainParams.Curve;
			var q = curve.DecodePoint(privateKeyParams.D.ToByteArrayUnsigned());

			var ecParameters = new ECParameters
			{
				Curve = ECCurve.CreateFromValue(domainParams.Curve.ToString()),
				D = privateKeyParams.D.ToByteArrayUnsigned(),
				Q = new ECPoint
				{
					X = q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(),
					Y = q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned()
				}
			};

			ECDsa ecdsa = ECDsa.Create();
			ecdsa.ImportParameters(ecParameters);

			return ecdsa;
		}
	}
	private static string GenerateRandomString(int length)
	{
		const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		var random = new Random();
		return new string(Enumerable.Repeat(chars, length)
			.Select(s => s[random.Next(s.Length)]).ToArray());
	}

	public static ECDsa ConvertToECDsa(string ecDsaString)
	{
		try
		{
			// Convert the string to bytes (assuming it's stored as ASCII or UTF-8)
			byte[] ecDsaBytes = Encoding.UTF8.GetBytes(ecDsaString);

			// Create an ECDsaCng object
			ECDsaCng ecdsa = new ECDsaCng();

			// Import the parameters from the byte array
			ecdsa.ImportSubjectPublicKeyInfo(ecDsaBytes, out _);

			// Return the ECDsa object
			return ecdsa;
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error converting ECDsa: " + ex.Message);
			throw;
		}
	}

	public static string GenerateCodeVerifier()
	{
		// Generate a cryptographically strong random string for code verifier
		using (var rng = RandomNumberGenerator.Create())
		{
			byte[] bytes = new byte[32];
			rng.GetBytes(bytes);
			return Base64UrlEncode(bytes);
		}
	}

	public static string GenerateCodeChallenge(string codeVerifier)
	{
		// Calculate the SHA256 hash of the code verifier and base64url encode it
		using (var sha256 = SHA256.Create())
		{
			byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
			return Base64UrlEncode(hashBytes);
		}
	}
	private static string Base64UrlEncode(byte[] input)
	{
		string base64 = Convert.ToBase64String(input);
		string base64Url = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
		return base64Url;
	}
}

public class Base64UrlJsonData
{
	public string Alg { get; set; }
	public string Enc { get; set; }
	public string Kid { get; set; }
	public string Typ { get; set; }
	public string Cty { get; set; }
	public string Zip { get; set; }
	public string Iv { get; set; }
	public string Tag { get; set; }
	public string Encrypted_key { get; set; }
}
