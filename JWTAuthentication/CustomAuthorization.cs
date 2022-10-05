using JWTAuthentication.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication
{
    [AttributeUsage(AttributeTargets.Method)]
    public class CustomAuthorization : Attribute, IAuthorizationFilter
    {
        private readonly IConfiguration _config;
        private readonly UserLogin userLogin;

        public CustomAuthorization(IConfiguration config, UserLogin users)
        {
            _config = config;
            userLogin = users;
        }

        public void OnAuthorization(AuthorizationFilterContext filterContext)
        {
            Microsoft.Extensions.Primitives.StringValues authTokens;
            Microsoft.Extensions.Primitives.StringValues authTokens2;

            filterContext.HttpContext.Request.Headers.TryGetValue("X-Username", out authTokens);
            filterContext.HttpContext.Request.Headers.TryGetValue("X-Password", out authTokens2);


            userLogin.Username = authTokens.FirstOrDefault();
            userLogin.Password = authTokens2.FirstOrDefault();

            var userModel = Authenticate(userLogin);
            if (userModel == null)
            {
                filterContext.Result = new JsonResult("Please Provide authToken")
                {
                    Value = new
                    {
                        Status = "Error",
                        Message = "Please Provide Valid Credentails"
                    },
                };
            }
            else
            {
                JwtSecurityToken _token = GenerateToken(userModel);

                filterContext.HttpContext.Response.Headers.Add("Token", new JwtSecurityTokenHandler().WriteToken(_token));
                filterContext.HttpContext.Response.Headers.Add("Expiry", _token.ValidTo.ToLocalTime().ToString());


                filterContext.Result = new JsonResult("Token Generted")
                {
                    Value = new
                    {
                        Status = "Ok",
                        Message = "Header generated",
                    },
                };


            }
        }
        private JwtSecurityToken GenerateToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,user.Username),
                new Claim(ClaimTypes.Role,user.Role)
            };

            var dt = DateTime.Now.AddSeconds(30);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: dt.ToLocalTime(),
                signingCredentials: credentials);

            return token;

        }

        private UserModel Authenticate(UserLogin userLogin)
        {
            var currentUser = UserConstants.Users.FirstOrDefault(x => x.Username.ToLower() ==
                userLogin.Username.ToLower() && x.Password == userLogin.Password);
            if (currentUser != null)
            {
                return currentUser;
            }
            return null;
        }
    }
}
