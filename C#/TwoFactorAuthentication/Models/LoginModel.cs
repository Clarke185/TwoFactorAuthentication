using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace TwoFactorAuthentication.Models {
    /// <summary>
    /// Class represents the login form as an object used by controllers to authenticate a user.
    /// </summary>
	public class LoginModel {
        [Required(AllowEmptyStrings = false, ErrorMessage = "You must enter a Username")]
        public string Username { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "You must enter a Password")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }
    }
}