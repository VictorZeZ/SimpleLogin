using Microsoft.AspNetCore.Identity;

namespace SimpleLogin.Models
{
    public class User : IdentityUser
    {
        public string Address { get; set; }
        public DateTime RegisterDate { get; set; } = DateTime.Now;
    }
}