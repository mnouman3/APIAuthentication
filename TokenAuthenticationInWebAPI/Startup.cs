using System;
using Microsoft.Owin;
using Owin;
using TokenAuthenticationInWebAPI.Models;
using Microsoft.Owin.Security.OAuth;
using System.Web.Http;

[assembly: OwinStartup(typeof(TokenAuthenticationInWebAPI.App_Start.Startup))]

namespace TokenAuthenticationInWebAPI.App_Start
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,

                //The Path For generating the Toekn
                TokenEndpointPath = new PathString("/token"),

                //Setting the Token Expired Time (30 minutes)
                AccessTokenExpireTimeSpan = TimeSpan.FromSeconds(60),

                //MyAuthorizationServerProvider class will validate the user credentials
                Provider = new MyAuthorizationServerProvider(),

                //For creating the refresh token and regenerate the new access token
                RefreshTokenProvider = new RefreshTokenProvider()
            };

            app.UseOAuthAuthorizationServer(options);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);
        }
    }
}