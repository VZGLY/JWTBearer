using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTBearer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        public ActionResult<string> GenerateToken()
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["jwt:secretKey"]));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            List<Claim> claims = new List<Claim>();

            //claims.Add(new Claim(ClaimTypes.Role, "Admin"));

            claims.Add(new Claim(ClaimTypes.Email, "Moi@Moi.moi"));

            claims.Add(new Claim(ClaimTypes.NameIdentifier, "12"));

            var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(14),signingCredentials: credentials);

            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
        }

        [Authorize]
        [HttpGet("Test")]
        public IActionResult TestToken()
        {
            var claim = User.Claims.Single(x => x.Type == ClaimTypes.NameIdentifier);

            Console.WriteLine(ClaimTypes.Email);

            Console.WriteLine(Convert.ToInt32(claim.Value) );
            return Ok();
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("TestAdmin")]
        public IActionResult TestAdminToken()
        {
            return Ok();
        }

    }
}
