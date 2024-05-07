using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

public class HttpHelper
{
	public static async Task<string> GetHttpsResponse_old(string method, string url, object body = null, string contentType = null, int timeout = 30000)
	{
		try
		{
			using (var client = new HttpClient())
			{
				client.Timeout = TimeSpan.FromMilliseconds(timeout);

				var request = new HttpRequestMessage(new HttpMethod(method.ToUpper()), url);


				if (body != null)
				{
					if (contentType != null && contentType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
					{
						request.Content = new StringContent(ConvertObjectToQueryString(body), Encoding.UTF8, contentType);
					}
					else
					{
						request.Content = new StringContent(body.ToString(), Encoding.UTF8, "application/json");
					}
				}

				var response = await client.SendAsync(request);

				response.EnsureSuccessStatusCode();

				return await response.Content.ReadAsStringAsync();
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error getting HTTPS response: " + ex.Message);
			throw;
		}
	}

	public static async Task<string> GetHttpsResponse(string method, string url, Dictionary<string, string> body = null, Dictionary<string, string> headers = null, int timeout = 30000)
	{
		try
		{
			using (var handler = new HttpClientHandler())
			{
				// Ignore SSL certificate validation
				handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

				using (var client = new HttpClient(handler))
				{
					client.Timeout = TimeSpan.FromMilliseconds(timeout);

					var request = new HttpRequestMessage(new HttpMethod(method.ToUpper()), url);

					// Set headers
					if (headers != null)
					{
						foreach (var header in headers)
						{
							// Skip setting Content-Type header
							if (header.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
							{
								continue;
							}
							request.Headers.Add(header.Key, header.Value);
						}
					}

					// Log request headers
					var requestHeader = JsonConvert.SerializeObject(headers, Formatting.Indented);

					// Set body
					if (body != null)
					{
						request.Content = new FormUrlEncodedContent(body);

						// Log request body
						var requestBody = await request.Content.ReadAsStringAsync();
					}

					var response = await client.SendAsync(request);

					response.EnsureSuccessStatusCode();

					return await response.Content.ReadAsStringAsync();
				}
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error getting HTTPS response: " + ex.Message);
			throw;
		}
	}
	private static string ConvertObjectToQueryString(object obj)
	{
		// Convert object to query string format
		var properties = obj.GetType().GetProperties();
		var queryString = new StringBuilder();
		foreach (var property in properties)
		{
			if (queryString.Length > 0)
			{
				queryString.Append("&");
			}
			queryString.Append(Uri.EscapeDataString(property.Name));
			queryString.Append("=");
			queryString.Append(Uri.EscapeDataString(property.GetValue(obj)?.ToString() ?? ""));
		}
		return queryString.ToString();
	}
}
