using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml.Linq;
using Newtonsoft.Json.Linq;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.IO;
using System.Reflection.Metadata;
using Microsoft.Extensions.Logging;
using System.Web;
using System.Text;
using System.Collections.Immutable;
using System.Linq;
using IdentityServer4.Models;
using System.Security.Cryptography;

namespace SingpassV4.Controllers
{
	public class SingpassController : ControllerBase
	{
		private readonly MyInfoConfig _config;
		private readonly HttpClient _httpClient;
		private readonly IHttpContextAccessor _httpContextAccessor;
		public SingpassController(IOptions<MyInfoConfig> myInfoConfig,
			IHttpContextAccessor httpContextAccessor)
		{
			_config = myInfoConfig.Value;
			_httpClient = new HttpClient();
			_httpContextAccessor = httpContextAccessor;

		}
		[Route("singpass/v4/authorize")]
		[HttpGet]
		public IActionResult AuthorizeAsync()
		{
			// Generate the code verifier and code challenge for PKCE flow
			var codeVerifier = SecurityHelper.GenerateCodeVerifier();
			// Generate code challenge
			var codeChallenge = SecurityHelper.GenerateCodeChallenge(codeVerifier);

			// Store code verifier in session
			_httpContextAccessor.HttpContext.Session.SetString("codeVerifier", codeVerifier);

			var url = GenerateAuthUrl(codeChallenge);
			return Ok(new
			{
				IsSuccess = true,
				ResponseCode = "0",
				ResponseMessage = "Singpass Authorization URL Generated",
				Data = new
				{
					auth_url = url,
					//id = pin.AppUserPinID
				}
			});

		}

		[Route("callback")]
		public async Task<IActionResult> CallbackAsync()
		{
			try
			{
				string temp = Request.Query["code"].ToString();
				return Ok(new
				{
					success = true,
					data = new
					{
						authcode = Request.Query["code"].ToString(),
					},
					message = "Code Received"
				});
			}
			catch (Exception ex)
			{
				return BadRequest(ex.Message);
			}
		}

		[Route("singpass/v4/getperson")]
		[HttpPost]
		public async Task<ActionResult> GetPersonAsync(GetPersonRequest request)
		{
			try
			{
				// Retrieve code verifier from session cache
				var codeVerifier = _httpContextAccessor.HttpContext.Session.GetString("codeVerifier");

				// Retrieve private signing key				
				var privateSigningKey = CryptoUtils.GetContentsOfPem(_config.DEMO_APP_CLIENT_PRIVATE_SIGNING_KEY);

				// Retrieve private encryption keys
				var privateEncryptionKey = CryptoUtils.GetContentsOfPem(_config.DEMO_APP_CLIENT_PRIVATE_ENCRYPTION_KEYS);


				// Call your service to retrieve person data
				var personData = await GetMyInfoPersonData(
					request.authcode,
					codeVerifier,
					privateSigningKey,
					privateEncryptionKey);



				// Return the person data
				return Ok(personData);
			}
			catch (Exception ex)
			{

				throw;
			}
		}
		#region Connector Method
		public string GenerateAuthUrl(string codeChallenge)
		{
			var clientID = _config.ClientId;
			var authApiUrl = _config.AuthorizeUrl;
			var redirectUrl = _config.RedirectUrl;
			var scope = _config.Scope;
			var purposeID = "demonstration";
			var authorizeUrl = $"{authApiUrl}?client_id={clientID}" +
					$"&scope={scope}" +
					$"&purpose_id={purposeID}" +
					$"&code_challenge={codeChallenge}" +
					$"&code_challenge_method=S256" +
					$"&redirect_uri={redirectUrl}";
			return authorizeUrl;

		}

		public async Task<object> GetMyInfoPersonData(string authCode, string codeVerifier, string privateSigningKey, string privateEncryptionKeys)
		{

			try
			{
		
				var accessToken = await GetAccessToken(authCode, codeVerifier, privateSigningKey);
				var personData = await GetPersonData(accessToken, privateEncryptionKeys);

				return personData;
			}
			catch (Exception error)
			{
				throw error;
			}
		}

		
		public async Task<string> GetAccessToken(string authCode, string codeVerifier, string privateSigningKey)
		{

			try
			{
				var clientID = _config.ClientId;
				var ECDsaKeyPair =await CryptoUtils.GenerateEphemeralKey();
				var jktThumbprint =await SecurityHelper.GenerateJwkThumbprint(ECDsaKeyPair.publicKey);
				var clientAssertion = CryptoUtils.GenerateClientAssertion(_config.TokenUrl, clientID, privateSigningKey, jktThumbprint);
				var strParams = new Dictionary<string, string>
				{
					{ "code", authCode },
					{ "code_verifier", codeVerifier },
					{ "client_assertion", clientAssertion },
					{ "grant_type", "authorization_code" },
					{ "client_id", clientID },
					{ "redirect_uri", _config.RedirectUrl },
					{ "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }
				};

				//ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
				//CryptoUtils.EphemeralKeyPair ephemeralKeyPair = new CryptoUtils.EphemeralKeyPair
				//{
				//	publicKey = ECDsaKeyPair.PublicKey,
				//	privateKey = ECDsaKeyPair.PrivateKey
				//};
				//var dPoP = await CryptoUtils.GenerateDPoP(_config.TokenUrl,authCode, "POST", ephemeralKeyPair);
				var dPoP = await CryptoUtils.GenerateDpopProof(_config.TokenUrl, "POST", ECDsaKeyPair, null);

				var strHeaders = new Dictionary<string, string>
				{
					{ "Content-Type", "application/x-www-form-urlencoded" },
					{ "Cache-Control", "no-cache" },
					{ "DPoP", dPoP }
				};

				var tokenURL = _config.TokenUrl;
				var accessToken = await HttpHelper.GetHttpsResponse("POST", tokenURL, strParams, strHeaders, 30000);

				return accessToken;

			}
			catch (Exception error)
			{
				throw error;
			}
		}

		public async Task<object> GetPersonData(string accessToken, string privateEncryptionKeys)
		{
			throw new NotImplementedException();
		}

		#endregion
	}

	public class EphemeralKeyPair
	{
		public string publickey { get; set; }
		public string privatekey { get; set; }

	}

	public class MyInfoConfig
	{
		public string ClientId { get; set; }
		public string ClientSecret { get; set; }
		public string URL { get; set; }
		public string AuthorizeUrl { get; set; }
		public string TokenUrl { get; set; }
		public string PersonUrl { get; set; }
		public string RedirectUrl { get; set; }
		public string Scope { get; set; }
		public string SubentityID { get; set; }
		public string AuthorizeJWKSUrl { get; set; }
		public string MyInfoJWKSURL { get; set; }
		public string DEMO_APP_CLIENT_PRIVATE_SIGNING_KEY { get; set; }
		public string DEMO_APP_CLIENT_PRIVATE_ENCRYPTION_KEYS { get; set; }
	}

	public class GetPersonRequest
	{
		public string state { get; set; }
		public string authcode { get; set; }
	}
}
