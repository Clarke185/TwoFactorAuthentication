using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace TwoFactorAuthentication.Controllers
{
    public class ErrorController : Controller
    {
        /// <summary>
        /// Method returns the PageNotFound view, used when a user attempts to access
        /// a page that does not exist.
        /// </summary>
        /// <returns>View: PageNotFound</returns>
        public ActionResult PageNotFound()
        {
            return View("PageNotFound");
        }
    }
}