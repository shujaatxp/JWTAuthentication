using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly UserLogin userLogin;
        public LoginController(IConfiguration config, UserLogin users)
        {
            _config = config;
            userLogin = users;
        }

        [ServiceFilter(typeof(CustomAuthorization))]        
        [HttpPost]
        public void Login()
        {
            //var username = HttpContext.Request.Headers["X-Username"];
            //var password = HttpContext.Request.Headers["X-Password"];

            //userLogin.Username = username;
            //userLogin.Password = password;

            //var user = Authenticate(userLogin);
            //if (user != null)
            //{
            //    var token = GenerateToken(user);
            //    return Ok(token);
            //}

            
        }

        
    }
}
