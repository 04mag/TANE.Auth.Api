namespace TANE.Auth.Api.Models
{
    public class UpdatePassword
    {
        public string Token { get; set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }
}