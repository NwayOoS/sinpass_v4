using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SingpassV4.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace SingpassV4
{
	public class Startup
	{
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//services.Configure<MvcOptions>(options =>
			//{
			//	options.Filters.Add(new RequireHttpsAttribute());
			//});
			//services.AddHttpsRedirection(options =>
			//{
			//	options.RedirectStatusCode = (int)HttpStatusCode.TemporaryRedirect;
			//	options.HttpsPort = 3001;
			//});
			services.AddHttpContextAccessor();
			services.AddSession(options =>
			{
				// Configure session options here
				options.IdleTimeout = TimeSpan.FromMinutes(30); // Set session timeout
				options.Cookie.HttpOnly = true; // Make session cookie accessible only through HTTP
												// Add any other session configuration options as needed
			});
			services.AddHttpContextAccessor();
			services.AddControllersWithViews();
			services.Configure<MyInfoConfig>(Configuration.GetSection("MyInfoConfig"));
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
				// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
				app.UseHsts();
			}
			app.UseHttpsRedirection();
			app.UseStaticFiles();

			app.UseRouting();
			app.UseSession();


			app.UseAuthorization();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllerRoute(
					name: "default",
					pattern: "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}
