using System.ComponentModel.DataAnnotations;

namespace SchoolApp.API.Data.ViewModels
{
    public class RegisterViewModel
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        [Required]
        public string EmailAddress { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]  
        public string Role { get; set; }

    }
}
