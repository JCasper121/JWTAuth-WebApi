using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SchoolApp.API.Data.Helpers;

namespace SchoolApp.API.Controllers
{
    [Authorize(Roles = UserRoles.Student + "," + UserRoles.Manager)]
    [ApiController]
    [Route("[controller]")]
    public class HomeController : Controller
    {
        public HomeController()
        {
            
        }

        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Welcome to HomeController");
        }

        [Authorize(Roles = UserRoles.Student)]
        [HttpGet("student")]
        public IActionResult GetStudent()
        {
            return Ok("Welcome to HomeController - Student");
        }

        [Authorize(Roles = UserRoles.Manager)]
        [HttpGet("manager")]
        public IActionResult GetManager()
        {
            return Ok("Welcome to HomeController - Manager");
        }
    }
}
