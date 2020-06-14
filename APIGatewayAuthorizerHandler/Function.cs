/*
* Copyright 2015-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
*
*     http://aws.amazon.com/apache2.0/
*
* or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

// Author: Caleb Petrick

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Amazon.Lambda.Core;
using APIGatewayAuthorizerHandler.Error;
using APIGatewayAuthorizerHandler.Model;
using APIGatewayAuthorizerHandler.Model.Auth;
using APIGatewayAuthorizerHandler.Utilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace APIGatewayAuthorizerHandler
{
    public class Function
    {
        public JwtSettings jwtSettings;
        /// <summary>
        /// A simple function that takes the token authorizer and returns a policy based on the authentication token included.
        /// </summary>
        /// <param name="input">token authorization received by api-gateway event sources</param>
        /// <param name="context"></param>
        /// <returns>IAM Auth Policy</returns>
        [LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]
        public AuthPolicy FunctionHandler(JObject jsonObject, ILambdaContext context)
        {
            try
            {
                //JObject jsonObject
                context.Logger.LogLine("json Object");
                context.Logger.LogLine(jsonObject.ToString());
                var input = jsonObject.ToObject<TokenAuthorizerContext>();
                //var input = jsonObject;
                jwtSettings = new JwtSettings(context);
                context.Logger.LogLine($"{nameof(input.AuthorizationToken)}: {input.AuthorizationToken}");
                context.Logger.LogLine($"{nameof(input.MethodArn)}: {input.MethodArn}");

                var jwtEncodedString = input.AuthorizationToken.Substring(7);

                var decodedToken = new JwtSecurityToken(jwtEncodedString: jwtEncodedString);
                context.Logger.LogLine($"Decoded Token: {decodedToken}");

                var expiry = decodedToken.ValidTo.ToLocalTime();
                context.Logger.LogLine($"Token expiry date: {expiry}");
                if (DateTime.Now.ToLocalTime() > expiry)
                {
                    context.Logger.LogLine("token expired");
                    throw new SecurityTokenExpiredException("token expired");
                }

                var isTokenValid = ValidateToken(jwtEncodedString, context);
                context.Logger.LogLine($"isTokenValid: {isTokenValid.ToString()}");
                if (!isTokenValid)
                {
                    throw new UnauthorizedException();
                }

                var concatenatedString = string.Join(" ,", decodedToken.Claims.Select(x => new { x.Type, x.Value }));
                context.Logger.LogLine($"User Claims: {concatenatedString}");
                var groupClaim = decodedToken.Claims.FirstOrDefault(x => x.Type == "cognito:groups");
                var principalId = "user|a1b2c3d4";

                // if the token is valid, a policy must be generated which will allow or deny access to the client

                // if access is denied, the client will receive a 403 Access Denied response
                // if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called

                // build apiOptions for the AuthPolicy
                var methodArn = ApiGatewayArn.Parse(input.MethodArn);
                var apiOptions = new ApiOptions(methodArn.Region, methodArn.RestApiId, methodArn.Stage);

                var policyBuilder = new AuthPolicyBuilder(principalId, methodArn.AwsAccountId, apiOptions);
                if (groupClaim != null)
                {
                    // we  get  the method arn  from aws endpoint in  api  gateway
                    if (groupClaim.Value.ToLower() == "admin")
                    {
                        context.Logger.LogLine($"Allow  all  method for user  with group: {groupClaim.Value}");

                        if (decodedToken.Claims.FirstOrDefault(x => x.Type == "custom:UserType").Value == "Trial" && decodedToken.Claims.FirstOrDefault(x => x.Type == "custom:Mobileverified") == null)
                        {
                            context.Logger.LogLine($"Allow update user , send verification code , verify mobile code apis for trial users");
                            // to allow access  to update user , send verification code , verify mobile code apis
                            policyBuilder.AllowMethod(HttpVerb.Put, "/usrmngmnt/*");
                            policyBuilder.AllowMethod(HttpVerb.Post, "/usrmngmnt/*/mobile-verify");
                            policyBuilder.AllowMethod(HttpVerb.Put, "/usrmngmnt/*/mobile-verify");
                            policyBuilder.AllowMethod(HttpVerb.Get, "/account");
                        }
                        else
                        {
                            context.Logger.LogLine($"Allow  all  method for user  with group: {groupClaim.Value}");
                            policyBuilder.AllowAllMethods();
                        }
                    }
                    else if (groupClaim.Value.ToLower() == "viewer")
                    {
                        context.Logger.LogLine($"Allow some resources user  with group : {groupClaim.Value}");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/account");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/lookups");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/senders");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign");

                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*");
                        policyBuilder.DenyMethod(HttpVerb.Delete, "/campaign/*");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/summary");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/lookup");

                        policyBuilder.AllowMethod(HttpVerb.Get, "/usrmngmnt/logout");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/usrmngmnt/changepassword");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/usrmngmnt/updateuser");

                        policyBuilder.AllowMethod(HttpVerb.Put, "/account/changePassword");
                        policyBuilder.AllowMethod(HttpVerb.Post, "/account/requestResetPassword");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/account/resetPassword");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/campaign/*/action");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/campaign/*/cancel");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/lookup");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/records");

                        policyBuilder.AllowMethod(HttpVerb.Post, "/export");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/export");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/export");
                        policyBuilder.AllowMethod(HttpVerb.Patch, "/export/*");

                        policyBuilder.AllowMethod(HttpVerb.Get, "/report");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/report/*/*");

                        policyBuilder.AllowMethod(HttpVerb.Get, "/report/*");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/report/report/export");
                    }
                    else if (groupClaim.Value.ToLower() == "contributor")
                    {
                        context.Logger.LogLine($"{groupClaim.Value} allow  to  access  this  resource {input.MethodArn}");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/account");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/lookups");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/senders");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/contacts");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/contacts/groups/*");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/contacts/groups");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign");
                        policyBuilder.AllowMethod(HttpVerb.Post, "/campaign/voice");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/campaign/voice");
                        policyBuilder.AllowMethod(HttpVerb.Post, "/campaign/sms");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/campaign/sms");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*");
                        policyBuilder.AllowMethod(HttpVerb.Delete, "/campaign/*");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/summary");

                        policyBuilder.AllowMethod(HttpVerb.Post, "/export");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/export");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/export");
                        policyBuilder.AllowMethod(HttpVerb.Patch, "/export/*");


                        policyBuilder.AllowMethod(HttpVerb.Get, "/usrmngmnt/logout");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/usrmngmnt/changepassword");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/usrmngmnt/updateuser");

                        policyBuilder.AllowMethod(HttpVerb.Put, "/account/changePassword");
                        policyBuilder.AllowMethod(HttpVerb.Post, "/account/requestResetPassword");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/account/resetPassword");
                        policyBuilder.AllowMethod(HttpVerb.Post, "/campaign");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/campaign/*/action");
                        policyBuilder.AllowMethod(HttpVerb.Put, "/campaign/*/cancel");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/lookup");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/campaign/*/records");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/contacts/lookups");

                        policyBuilder.AllowMethod(HttpVerb.Get, "/report");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/report/*/*");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/report/*");
                        policyBuilder.AllowMethod(HttpVerb.Get, "/report/report/export");
                    }
                    else
                    {
                        policyBuilder.DenyAllMethods();
                        context.Logger.LogLine($"Deny all methods to group : {groupClaim.Value}");
                    }
                }
                else
                {
                    policyBuilder.DenyAllMethods();
                }

                // finally, build the policy
                var authResponse = policyBuilder.Build();
                authResponse.Context.Add("key", "value");
                authResponse.Context.Add("number", 5);
                authResponse.Context.Add("bool", true);

                return authResponse;
            }
            catch (Exception ex)
            {
                // log the exception and return a 401
                context.Logger.LogLine(ex.StackTrace);
                context.Logger.LogLine(ex.Message);
                throw new UnauthorizedException();
            }
        }

        private bool ValidateToken(string authToken, ILambdaContext context)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = jwtSettings.TokenValidationParameters;
            SecurityToken validatedToken;
            IPrincipal principal = tokenHandler.ValidateToken(authToken, validationParameters, out validatedToken);
            return true;
        }

    }
}
