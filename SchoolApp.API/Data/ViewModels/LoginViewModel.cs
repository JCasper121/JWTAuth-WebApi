using System.ComponentModel.DataAnnotations;

namespace SchoolApp.API.Data.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        public string EmailAddress { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
