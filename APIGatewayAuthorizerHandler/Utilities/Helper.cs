using System;
using System.Collections.Generic;
using System.Text;

namespace APIGatewayAuthorizerHandler.Utilities
{
    public static class Helper
    {
        public static string GetEnvironmentVariable(string key)
        {
            return Environment.GetEnvironmentVariable(key);
        }
    }
}
