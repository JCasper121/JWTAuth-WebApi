using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SchoolApp.API.Data.Helpers;

namespace SchoolApp.API.Controllers
{
    [Authorize(Roles = UserRoles.Student)]
    [ApiController]
    [Route("[controller]")]
    public class StudentController : Controller
    {
        public StudentController()
        {
            
        }

        [HttpGet]
        public IActionResult Index()
        {
            return Ok("Welcome to StudentController");
        }
    }
}
