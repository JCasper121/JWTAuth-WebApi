using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SchoolApp.API.Data;
using SchoolApp.API.Data.Helpers;
using SchoolApp.API.Data.Models;
using SchoolApp.API.Data.ViewModels;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SchoolApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly TokenValidationParameters _tokenValidationParameters;

        public AuthenticationController(IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            AppDbContext context,
             TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _configuration = configuration;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel registerViewModel)
        {
            if (!ModelState.IsValid)
                return BadRequest("Please provide all the required fields");

            var userExists = await _userManager.FindByEmailAsync(registerViewModel.EmailAddress);

            if (userExists != null)
                return BadRequest($"User {registerViewModel.EmailAddress} already exists.");

            ApplicationUser newUser = new()
            {
                FirstName = registerViewModel.FirstName,
                LastName = registerViewModel.LastName,
                Email = registerViewModel.EmailAddress,
                UserName = registerViewModel.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            
            var result = await _userManager.CreateAsync(newUser, registerViewModel.Password);

            if (!result.Succeeded)
                return BadRequest("User could not be created.");
            else
            {
                switch (registerViewModel.Role)
                {
                    case UserRoles.Manager:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Manager); break;
                    case UserRoles.Student:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Student); break;
                    default:
                        break;
                }
                 return Ok("User created.");
            }
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel loginViewModel)
        {
            if (!ModelState.IsValid)
                return BadRequest("Please provide all required fields");
            var userExists = await _userManager.FindByEmailAsync(loginViewModel.EmailAddress);
            
            if (userExists != null && await _userManager.CheckPasswordAsync(userExists, loginViewModel.Password))
            {
                var tokenValue = await GenerateJwtTokenAsync(userExists, null);
                return Ok(tokenValue);
            }
            
            return Unauthorized();
        }
        
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestViewModel tokenRequestViewModel)
        {
            if (!ModelState.IsValid)
                return BadRequest("Please provide all required fields");
            var result = await VerifyAndGenerateTokenAsync(tokenRequestViewModel);

            return Ok(result);
        }

        private async Task<AuthResultViewModel> VerifyAndGenerateTokenAsync(TokenRequestViewModel tokenRequestViewModel)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequestViewModel.RefreshToken);
            var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

            try
            {
                var tokenCheckResult = jwtTokenHandler
                    .ValidateToken(tokenRequestViewModel.Token,
                    _tokenValidationParameters, 
                    out var validatedToken);

                return await GenerateJwtTokenAsync(dbUser, storedToken);
            }catch(SecurityTokenExpiredException ex)
            {
                if(storedToken.DateExpire >= DateTime.UtcNow)
                {
                    return await GenerateJwtTokenAsync(dbUser, storedToken);
                }else
                {
                    return await GenerateJwtTokenAsync(dbUser, null);
                }
            }
        }

        private async Task<AuthResultViewModel> GenerateJwtTokenAsync(ApplicationUser user, RefreshToken rToken)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //Add user role claims
            var userRoles = await _userManager.GetRolesAsync(user);

            foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:SecretKey"]));
         
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddMinutes(5),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);
            
            if(rToken != null)
            {
               return new AuthResultViewModel()
               {
                   Token = jwtToken,
                   RefreshToken = rToken.Token,
                   ExpiresAt = token.ValidTo
               };
            }

            var refreshToken = new RefreshToken()
            {
                JwtTokenId = token.Id,
                IsRevoked = false,
                UserId = user.Id,
                DateAdded = DateTime.UtcNow,
                DateExpire = DateTime.UtcNow.AddMonths(6),
                Token = Guid.NewGuid().ToString() + '-' + Guid.NewGuid().ToString()
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            
            return new AuthResultViewModel()
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = token.ValidTo
            };
        }

    }
}
