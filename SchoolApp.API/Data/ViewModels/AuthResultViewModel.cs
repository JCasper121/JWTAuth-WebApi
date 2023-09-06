using SchoolApp.API.Data.Models;

namespace SchoolApp.API.Data.ViewModels
{
    public class AuthResultViewModel
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}
