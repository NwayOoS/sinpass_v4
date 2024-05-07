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

namespace SingpassV4.Controllers
{
	public class SingpassTempController : ControllerBase
	{
		private readonly MyInfoConfig _config;
		private readonly HttpClient _httpClient;
		private readonly IHttpContextAccessor _httpContextAccessor;
		public SingpassTempController(IOptions<MyInfoConfig> myInfoConfig,
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
		

		public async Task<object> GetMyInfoPersonData(string authCode, string codeVerifier, string privateSigningKey, List<string> privateEncryptionKeys)
		{
			
			try
			{
				var sessionEphemeralKeyPair = CryptoUtils.GenerateSessionKeyPair();

				var ECPrivateKey = sessionEphemeralKeyPair.PrivateKey;
				var ECPublicKey = sessionEphemeralKeyPair.PublicKey;

				//var ephemeralKeyPair = new EphemeralKeyPair
				//{
				//	publickey = sessionEphemeralKeyPair.PublicKey,
				//	privatekey = sessionEphemeralKeyPair.PrivateKey
				//};

				var accessToken = await GetAccessToken(authCode, codeVerifier, ephemeralKeyPair, privateSigningKey);
				var personData = await GetPersonData(accessToken, ephemeralKeyPair, privateEncryptionKeys);

				return personData;
			}
			catch (Exception error)
			{
				throw error;
			}
		}

		public async Task<string> GetAccessToken(string authCode, string codeVerifier, EphemeralKeyPair sessionEphemeralKeyPair, string privateSigningKey)
		{
			
			try
			{
				var clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
				var jktThumbprint = await SecurityHelper.GenerateJwkThumbprint(sessionEphemeralKeyPair.publickey);
				var clientAssertion = await SecurityHelper.GenerateClientAssertion(_config.TokenUrl, _config.ClientId, privateSigningKey, jktThumbprint, "");
				var strParams = $"grant_type=authorization_code" +
					$"&code={authCode}" +
					$"&redirect_uri={_config.RedirectUrl}" +
					$"&client_id={_config.ClientId}" +
					$"&code_verifier={codeVerifier}" +
					$"&client_assertion_type={clientAssertionType}" +
					$"&client_assertion={clientAssertion}";

				var dPoP = await SecurityHelper.GenerateDpop(_config.TokenUrl, null, "POST", sessionEphemeralKeyPair.privatekey);

				var strHeaders = $"Content-Type=application/x-www-form-urlencoded&Cache-Control=no-cache&DPoP={dPoP}";
				var headers = HttpUtility.ParseQueryString(strHeaders);

				var tokenURL = _config.TokenUrl;
				var accessToken = await HttpHelper.GetHttpsResponse("POST", tokenURL, headers, strParams, 30000);

				return accessToken;
			}
			catch (Exception error)
			{
				//Logger.Error("getAccessToken - Error: ", error);
				throw error;
			}
		}

		public async Task<object> GetPersonData(string accessToken, EphemeralKeyPair sessionPopKeyPair, List<string> privateEncryptionKeys)
		{
			try
			{
				
				var callPersonRequestResult = await GetPersonDataWithToken(accessToken, sessionPopKeyPair, privateEncryptionKeys);

				return callPersonRequestResult;
			}
			catch (Exception error)
			{
				//Logger.Error("getPersonData - Error: ", error);
				throw error;
			}
		}

		

		public async Task<object> CallPersonAPI(string sub, string accessToken, EphemeralKeyPair sessionEphemeralKeyPair)
		{
			try
			{
				string urlLink;

				// Code to handle Myinfo Biz Entity Person URL
				if (_config.PersonUrl.Contains("biz"))
				{
					string[] subTemp = sub.Split('_');
					string uen = subTemp[0];
					string uuid = subTemp[1];
					urlLink = _config.PersonUrl + "/" + uen + "/" + uuid;
				}
				else
				{
					urlLink = _config.PersonUrl + "/" + sub;
				}

				string cacheCtl = "no-cache";
				string method = "GET"; // Define the HTTP method here or fetch from constant

				// Assemble params for Person API
				string strParams = "scope=" + Uri.EscapeDataString(_config.Scope);
				// Append subentity if configured
				if (!string.IsNullOrEmpty(_config.SubentityID))
				{
					strParams += "&subentity=" + Uri.EscapeDataString(_config.SubentityID);
				}

				// Assemble headers for Person API
				Dictionary<string, string> headers = new Dictionary<string, string>();
				headers["Cache-Control"] = cacheCtl;

				// Generate ath to append into DPoP
				//byte[] ath = Encoding.UTF8.GetBytes(accessToken); // Assuming accessToken is already base64 URL encoded
				string dpopToken = await SecurityHelper.GenerateDpop(urlLink, accessToken, method, sessionEphemeralKeyPair.privatekey);
				headers["dpop"] = dpopToken;

				headers["Authorization"] = "DPoP " + accessToken;

				Console.WriteLine("Authorization Header for MyInfo Person API: " + string.Join(",", headers));

				// Define the base URL
				string baseUrl = _config.PersonUrl;

				// Update URL to include uen for Myinfo Biz
				string requestPath = _config.PersonUrl.Contains("biz") ? $"{urlLink}/{sub}?{strParams}" : $"{urlLink}?{strParams}";

				// Invoking HTTPS to do GET call
				using (HttpClient client = new HttpClient())
				{
					HttpResponseMessage response = await client.GetAsync(baseUrl + requestPath);
					response.EnsureSuccessStatusCode(); // Throw on error code
					string responseBody = await response.Content.ReadAsStringAsync();
					return responseBody;
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.Message);
				throw;
			}
		}

		public async Task<object> GetPersonDataWithToken(string accessToken, EphemeralKeyPair sessionEphemeralKeyPair, List<string> privateEncryptionKeys)
		{
			try
			{
				// Decode and verify token
				var decodedToken = await SecurityHelper.VerifyJWS(accessToken, _config.AuthorizeJWKSUrl);
				Console.WriteLine("Decoded Access Token (from MyInfo Token API): " + decodedToken);

				if (decodedToken == null)
				{
					Console.WriteLine("Error: Invalid token");
					throw new Exception("ERROR_INVALID_TOKEN");
				}

				var uinfin = decodedToken;//to check
				if (uinfin == null)
				{
					Console.WriteLine("Error: UINFIN not found");
					throw new Exception("ERROR_UINFIN_NOT_FOUND");
				}

				// Call Person API
				var personResult = await CallPersonAPI(uinfin.ToString(), accessToken, sessionEphemeralKeyPair);

				object decryptedResponse = null;
				if (personResult != null)
				{
					Console.WriteLine("MyInfo PersonAPI Response (JWE+JWS): " + personResult);

					// Test decryption with different keys passed in
					foreach (var privateKey in privateEncryptionKeys)
					{
						var jws = await SecurityHelper.DecryptJWEWithKey("personResult", privateKey);///^^^ to change
						if (jws != "ERROR_DECRYPT_JWE")
						{
							Console.WriteLine("Decrypted JWE: " + jws);
							decryptedResponse = jws;
							break;
						}
					}
				}
				else
				{
					Console.WriteLine("Error: ERROR");
					throw new Exception("ERROR");
				}

				object decodedData = null;

				if (decryptedResponse != null)
				{
					Console.WriteLine("Error: Invalid data or signature");
					throw new Exception("ERROR_INVALID_DATA_OR_SIGNATURE");
				}

				// Verify the signature of the decrypted JWS
				decodedData = await SecurityHelper.VerifyJWS(decryptedResponse.ToString(), _config.MyInfoJWKSURL);

				// Successful. Return data back to frontend
				//Console.WriteLine("Person Data (JWE Decrypted + JWS Verified): " + JsonSerializer.Serialize(decodedData));
				return decodedData;
			}
			catch (Exception ex)
			{
				throw ex;
			}
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
