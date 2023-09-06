using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SchoolApp.API.Data.Helpers;

namespace SchoolApp.API.Controllers
{
    [Authorize(Roles = UserRoles.Manager)]
    [ApiController]
    [Route("[controller]")]
    public class ManagementController : Controller
    {
        public ManagementController()
        {
            
        }

        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Welcome to ManagementController");
        }
    }
}
