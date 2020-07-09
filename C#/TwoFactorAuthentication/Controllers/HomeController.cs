using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Web;
using System.Web.Mvc;
using TwoFactorAuthentication.Models;

namespace TwoFactorAuthentication.Controllers {
	public class HomeController : Controller {

		/// <summary>
		/// Method returns the Index view for the Home controller used as the
		/// landing page and home page for the application.
		/// </summary>
		/// <returns></returns>
		public ActionResult Index() {
			return View("Index");
		}
	}
}