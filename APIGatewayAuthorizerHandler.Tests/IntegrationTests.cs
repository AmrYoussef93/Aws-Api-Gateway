using System.Linq;
using Amazon.Lambda.TestUtilities;
using APIGatewayAuthorizerHandler.Model;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace APIGatewayAuthorizerHandler.Tests
{
    public class IntegrationTests
    {
        [Fact]
        public void CallingFunctionWithAnyTokenReturnDenyAllPolicy()
        {
            var function = new Function();
            var request = SampleRequest();
            var lambdaContext = new TestLambdaContext();
            string json = JsonConvert.SerializeObject(request);
            JObject jObject = JObject.Parse(json);
            var result = function.FunctionHandler(jObject, lambdaContext);

            Assert.Equal(result.PrincipalId, "user|a1b2c3d4");
            var firstStatement = result.PolicyDocument.Statement.First();
            Assert.Equal("Deny", firstStatement.Effect);
            Assert.Equal("arn:aws:execute-api:ap-southeast-2:123123123123:123sdfasdf12/prod/*/*", firstStatement.Resource);
        }

        private static TokenAuthorizerContext SampleRequest(string type = "TOKEN", 
            string token = "Bearer eyJraWQiOiJoc3ljYWFpQTF0ZUFSVGFLeGJ0MnppT1BSelhCWU9ibmV2U2srcE9yajM0PSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJmYjU1NjhkOS04ZWM2LTRmZDAtODFmMy1hNTBhYmRjMjk5YTciLCJjb2duaXRvOmdyb3VwcyI6WyJhZG1pbiJdLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiY3VzdG9tOk9uYm9hcmRpbmciOiJUcmlhbCIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0dzbjhaeVNsMSIsImNvZ25pdG86dXNlcm5hbWUiOiJ5b2hleGluNDIwQG1haWxmaWxlLm9yZyIsImN1c3RvbTpDYWxsYmFja1VybCI6Ind3dy5jb25zb2xlLmNlcXVlbnMuY29tIiwiY3VzdG9tOkRpc3BsYXlOYW1lIjoiTWFyaWFtIHRyaWFsIHZlcmlmeSIsImN1c3RvbTpUaW1lWm9uZSI6IlVUQyAyIiwiYXVkIjoiM2E4Mzhmam9wNDMza2pkZTlubGFkaDJoZ2UiLCJldmVudF9pZCI6IjFlNTdjYTA0LWNiODYtNDVjZC05Zjc2LWE3OWZhMGE3NzNkOSIsImN1c3RvbTpVc2VyVHlwZSI6IlRyaWFsIiwidG9rZW5fdXNlIjoiaWQiLCJjdXN0b206RXhwaXJlSW4iOiIzXC8xNlwvMjAyMCAxMjo1MTowNCBQTSIsImF1dGhfdGltZSI6MTU3NjU3Mzg3MCwiY3VzdG9tOkFjY291bnRJRCI6IjUyNzgwIiwiZXhwIjoxNTc2NTc3NDcwLCJpYXQiOjE1NzY1NzM4NzAsImVtYWlsIjoieW9oZXhpbjQyMEBtYWlsZmlsZS5vcmcifQ.Rh7WluY1HbuKyFOMY3NPEKtKvprpKZ0pNKNfR4nWIWMm4HsgOLANmN0MXM9h-gotkhL4H-YzgsURl9OKbeqglRjtkN-UudD_aYf_VKz2P653JTwMuZHGTItbKUg0ByKuukR2dumVyZabdxwFJft7WMW24GXIwv5HoKojIJxhTHWlimplUnY8TkCPmZS8WVzzXUJxehbdSyL2NzG1XisEeqA0dYF9DWu0F_v8yCn_YCjYvy2e9F7chce1j--CEnWfiBeYDYwavSEtT4EsR_Wn40jlPl7rOQ12m1gcyUNpEeZ4yjI8mF9TCx9ftclq4vnGP2GyNDSuc1jOVBfzONzBfA",
            string region = "us-east-1",
            string accoundId = "669791164395",
            string restApiId = "zjw4yf17g4",
            string stage = "*",
            string verb = "GET")
        {
            string json = $@"{{ ""Type"": ""{type}"", ""AuthorizationToken"": ""{token}"", ""MethodArn"": ""arn:aws:execute-api:us-east-1:937907730099:p9tg3ebif2/prod/GET/contacts/groups"" }}";
            return JsonConvert.DeserializeObject<TokenAuthorizerContext>(json);
        }
    }
}
