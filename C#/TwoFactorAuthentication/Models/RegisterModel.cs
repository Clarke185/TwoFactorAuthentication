using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace TwoFactorAuthentication.Models {
	/// <summary>
	/// Class represents a form as an object filled in by a user during the registration process.
	/// All information is required to complete the registration process.
	/// </summary>
	public class RegisterModel {
		[DataType(DataType.Text)]
		[StringLength(50, ErrorMessage = "The Username must be between 8 and 50 characters.", MinimumLength = 8)]
		[Required(ErrorMessage = "You must enter a Username")]
		[Display(Name = "Username*")]
		public string Username { get; set; }

		[StringLength(50, ErrorMessage = "Password must be between 8 and 50 characters.", MinimumLength = 8)]
		[DataType(DataType.Password)]
		[Required(ErrorMessage = "You must enter a Password")]
		[Display(Name = "Password*")]
		public string Password { get; set; }

		[StringLength(50, ErrorMessage = "Password must be between 8 and 50 characters.", MinimumLength = 8)]
		[Display(Name = "Confirm Password*")]
		[DataType(DataType.Password)]
		[Required(ErrorMessage = "You must confirm your Password")]
		[Compare("Password", ErrorMessage = "Passwords do not match.")]
		public string ConfirmPassword { get; set; }

		[DataType(DataType.EmailAddress)]
		[Display(Name = "Email Address*")]
		[StringLength(50, ErrorMessage = "The Email Address cannot be longer than 200 characters.")]
		[Required(ErrorMessage = "You must enter an Email Address")]
		public string EmailAddress { get; set; }

		[DataType(DataType.EmailAddress)]
		[Display(Name = "Confirm Email*")]
		[Required(ErrorMessage = "You must confirm your Email Address")]
		[Compare("EmailAddress", ErrorMessage = "Emails do not match.")]
		public string ConfirmEmail { get; set; }
	}
}