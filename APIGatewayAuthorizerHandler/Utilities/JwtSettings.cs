using Amazon.Lambda.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace APIGatewayAuthorizerHandler.Utilities
{
    public class JwtSettings
    {

        private ILambdaContext _context;
        public JwtSettings(ILambdaContext context)
        {
            _context = context;
        }
        // for live environment get values from EnvironmentVariable
        // for QC environment get value from commentted string
        public string Issuer
        {
            get
            {
              
                return Environment.GetEnvironmentVariable("Issuer");
                //"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Gsn8ZySl1";
                //Environment.GetEnvironmentVariable("Issuer");
            }
        }

        public string Key
        {
            get
            {
                return Environment.GetEnvironmentVariable("Key");
                //"hl6D5SjVGKHMWgDGLTPFTRT8J4HmPT0dVl5jk8ZmTSduPIsk61R_qVrsoEgpCBvZnnO3AG39m3VgrRs3HFondh5cOXrJFr4bTkq38gwd5DIVoPCJTuWqPsryK5D4RU9UdY9Q9c3xlByaXg24gSVUdclK_dCMPbNYCJEHYCccqq1_0Wz152TUDzOfpGxw1bN0H7ewpw3QiACok3DqIRQxzT3-tnIHsimK2ZZ25cBXsEYhVMxWCphnX_i1_lY44MMIh25-12MxrLxDTKcNi5jCuauoIGmPP_ZDr90N0YkOuX9U1PQB-CtHHuQaW8c6kOi0Q1I6eHSSbtWAfET9MQwYXQ";
                //Environment.GetEnvironmentVariable("Key");
            }
        }

        public string Expo
        {
            get
            {
                return Environment.GetEnvironmentVariable("Expo");
                //"AQAB";
                //Environment.GetEnvironmentVariable("Expo");
            }
        }

        public RsaSecurityKey SigningKey
        {
            get
            {
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(
                    new RSAParameters()
                    {
                        //key
                        Modulus = Base64UrlEncoder.DecodeBytes(this.Key),
                        Exponent = Base64UrlEncoder.DecodeBytes(this.Expo)
                    });

                return new RsaSecurityKey(rsa);
            }
        }

        public TokenValidationParameters TokenValidationParameters
        {
            get
            {
                // Basic settings - signing key to validate with, audience and issuer.
                return new TokenValidationParameters
                {
                    IssuerSigningKey = SigningKey,
                    ValidIssuer = Issuer,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidateAudience = true,
                    ValidAudience = Environment.GetEnvironmentVariable("UserPoolClientId")
                    //"3a838fjop433kjde9nladh2hge"
                    //Environment.GetEnvironmentVariable("UserPoolClientId")
                };
            }
        }

    }
}
