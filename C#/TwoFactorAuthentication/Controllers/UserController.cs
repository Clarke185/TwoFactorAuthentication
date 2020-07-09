using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using TwoFactorAuthentication.Models;


namespace TwoFactorAuthentication.Controllers
{
    public class UserController : Controller
    {
        /// <summary>
        /// Initial page for registration, if a logged in user attempts to access the page, they are redirected
        /// </summary>
        /// <returns>View representing that page that the user should direct to</returns>
        public ActionResult Register() {
            if (User.Identity.IsAuthenticated) {
                return RedirectToAction("UserProfile", "User");
            } else {
                return View("Register");
            }
        }

        /// <summary>
        /// POST method takes a registration object, verifys the object, adds it to the database, and finally sends
        /// a verification email to the relevant user.
        /// </summary>
        /// <param name="RegUser">Object representing the registration form filled in by the user</param>
        /// <returns>View for the path required with the relevant success/error message</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel RegUser) {
            if (ModelState.IsValid) {
                if (UsernameExists(RegUser.Username)) {
                    TempData["Message"] = "Username already taken.";
                    TempData["Status"] = false;
                    return View();
                }

                var hash_and_salt = Helpers.Hashing.GenerateHash(RegUser.ConfirmPassword);
                user thisUser = new user {
                    id = Guid.NewGuid(),
                    username = RegUser.Username,
                    hashed_password = hash_and_salt[0],
                    salt = new Guid(hash_and_salt[1]),
                    email = RegUser.EmailAddress,
                    bio = null,
                    verified = false,
                    activation_code = Guid.NewGuid()
                };

                List<string> macs = GetDevices();
                List<device> devices = new List<device>();
                foreach (string address in macs) {
                    if (!String.IsNullOrEmpty(address)) {
                        devices.Add(new device {
                            id = Guid.NewGuid(),
                            user_id = thisUser.id,
                            device_mac = address
                        });
                    }
                }

                using (TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities()) {
                    entity.users.Add(thisUser);
                    foreach (device dev in devices) {
                        entity.devices.Add(dev);
                    }
                    entity.SaveChanges();
                    SendRegistrationVerificationEmail(thisUser.email, thisUser.activation_code.ToString());
                    TempData["Status"] = true;
                    TempData["Message"] = "User added successfully! Please check your registered email for your verification link. Once verified you may log in!";
                    return RedirectToAction("Index", "Home");
                }
            } else {
                TempData["Status"] = false;
                TempData["Message"] = "Invalid Request";
            }
            return View(RegUser);
        }

        /// <summary>
        /// Default action result method for users logging in, if already logged in then
        /// redirect the user to their profile, otherwise allow them to log in.
        /// </summary>
        /// <returns>View determined by the user's login status</returns>
        public ActionResult Login() {
            if (User.Identity.IsAuthenticated) {
                return RedirectToAction("UserProfile", "User");
            } else {
                return View("Login");
            }
        }

        /// <summary>
        /// POST methods verifies a Login object and if the credentials match, created an 
        /// encrypted authentication ticket and add it as a cookie to the current session.
        /// </summary>
        /// <param name="login">object representing the filled in credentials in the 
        /// login view</param>
        /// <returns>View determined by the user's login credentials. If correct then 
        /// Home, Login otherwise</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel login) {
            if (ModelState.IsValid && UsernameExists(login.Username)) {
                using (TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities()) {
                    user user = entity.users
                        .Where(s => s.username.Equals(login.Username))
                        .FirstOrDefault();

                    if (user.verified.Equals(false)) {
                        TempData["Message"] = "You must verify your account before attempting to log in. Please check your registered email.";
                        TempData["Status"] = false;
                        return View("Login");
                    }

                    List<string> mac_addresses = GetDevices();
                    List<device> devices = entity.devices
                        .Where(d => d.user_id == user.id)
                        .ToList();

                    bool knownDevice = false;
                    foreach(device dev in devices) {
                        foreach (string mac in mac_addresses) {
                            if (dev.device_mac.Equals(mac)) {
                                knownDevice = true;
                            }
                        }
                    }

                    if (knownDevice == false) {
                        TempData["Message"] = "This is an unknown device, please check your registered email to verify this device and then try logging in again.";
                        TempData["Status"] = false;
                        SendDeviceVerificationEmail(user.email, mac_addresses, user.activation_code.ToString());
                        return View("Login");
                    }

                    byte[][] loginResults = Helpers.Hashing.GenerateHash(login.Password, user.salt);
                    if (loginResults[0].SequenceEqual(user.hashed_password)) {
                        //Success! Let's get their details and if they chose to, remember them.
                        int timeout = login.RememberMe ? 525600 : 20; // 525600 min = 1 year
                        FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(login.Username, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);

                        HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);

                        TempData["Message"] = "Successfully logged in.";
                        TempData["Status"] = true;
                        return RedirectToAction("UserProfile", "User");
                    }
                }
            }
            TempData["Message"] = "Unable to login. Please check your username and password";
            TempData["Status"] = false;
            return View("Login");
        }

        /// <summary>
        /// Method signs out the currently authenticated user and redirects them to the 
        /// Login view
        /// </summary>
        /// <returns>Login view regardless</returns>
        [Authorize]
        public ActionResult Logout() {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }

        /// <summary>
        /// Method verifies the currently logged in user, if so then authenticate them and direct
        /// them to their profile, otherwise to the Login view.
        /// </summary>
        /// <returns>View determined by the user's authenticated status.</returns>
        [Authorize]
        public ActionResult UserProfile() {
            if (User.Identity.IsAuthenticated) {
                //FormsIdentity formsIdentity = HttpContext.Current.User.Identity as FormsIdentity;
                FormsIdentity formsIdentity = HttpContext.User.Identity as FormsIdentity;
                FormsAuthenticationTicket ticket = formsIdentity.Ticket;
                using (TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities()) {
                    user user = entity.users.Where(u => u.username.Equals(ticket.Name)).FirstOrDefault();
                    return View(user);
                }
            } else {
                return RedirectToAction("Login", "User");
            }
        }

        /// <summary>
        /// Boolean method determines whether a username matching the string input exists
        /// in the database context.
        /// </summary>
        /// <param name="inputUsername">string value of the username to find</param>
        /// <returns>boolean value, true if exists, false otherwise</returns>
        [NonAction]
        private static bool UsernameExists(string inputUsername) {
            TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities();
            if(entity.users.Where(u => u.username == inputUsername).Any()) {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Boolean method determines whether an email address matching the string input exists
        /// in the database context.
        /// </summary>
        /// <param name="inputEmail">string value of the email address to find</param>
        /// <returns>boolean value, true if exists, false otherwise</returns>
        [NonAction]
        private static bool EmailExists(string inputEmail) {
            TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities();
            if(entity.users.Where(e => e.email == inputEmail).Any()) {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Method verifies a user account via a link clicked by the end user through an email.
        /// Specific format is required, hence the email link. Activation code is unique to a user
        /// that then updates their verified status on the database context.
        /// </summary>
        /// <param name="id">string value representing the user's activation code</param>
        /// <returns>Home view with success/error message depending on whether the user has been
        ///     verified or not</returns>
        [HttpGet]
        public ActionResult VerifyAccount(string id) {
            using (TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities()) {
                //Prevents having to login if you're signed out to verify the device.
                entity.Configuration.ValidateOnSaveEnabled = false;

                user thisUser = new user();
                try {
                    thisUser = entity.users.Where(a => a.activation_code == new Guid(id)).FirstOrDefault();
                } catch (Exception e) {
                    Debug.WriteLine(e.Message);
                    TempData["Status"] = false;
                    TempData["Message"] = "Activation code is invalid.";
                    return RedirectToAction("Index", "Home");
                }
                
                if (thisUser != null) {
                    if (thisUser.verified.Equals(true)) {
                        TempData["Status"] = false;
                        TempData["Message"] = "This account has already been verified.";
                        return RedirectToAction("Index", "Home");
                    }

                    thisUser.verified = true;
                    entity.SaveChanges();
                    TempData["Status"] = true;
                    TempData["Message"] = "Account successfully verified.";
                } else {
                    TempData["Status"] = false;
                    TempData["Message"] = "Unable to verify account.";
                    return RedirectToAction("Index", "Home");
                }
            }
            return View();
        }

        /// <summary>
        /// Method verifies a device given an id that contains the user's activation code, as well
        /// as any MAC addresses found. Each MAC address found is verified and added to the user.
        /// </summary>
        /// <param name="id">string value containing the activation code, and THEN any relevant MAC
        /// addresses in the format code__mac_mac_mac</param>
        /// <returns>Home view regardless of outcome</returns>
        public ActionResult VerifyDevice(string id) {
            using (TwoFactorAuthenticationEntities entity = new TwoFactorAuthenticationEntities()) {
                //Prevents having to login if you're signed out to verify the device.
                entity.Configuration.ValidateOnSaveEnabled = false;

                //Since we are passing both the activation code and device mac address, split them.
                string[] separator = {"_"};
                string[] separated = id.Split(separator,StringSplitOptions.RemoveEmptyEntries);
                string idForUser = separated[0].ToString().ToUpper();

                user thisUser = new user();
                try {
                    thisUser = entity.users.Where(a => a.activation_code == new Guid(idForUser)).FirstOrDefault();
                } catch (Exception e) {
                    Debug.WriteLine(e.Message);
                    TempData["Status"] = false;
                    TempData["Message"] = "Activation code is invalid.";
                    return RedirectToAction("Index", "Home");
                }
                
                if(thisUser != null){
                    try {
                        List<device> devices = entity.devices
                            .Where(d => d.user_id == thisUser.id)
                            .ToList();
                        foreach(var device in devices) {
                            for (int i = 1; i < separated.Length; i++) {
                                if (device.device_mac == separated[i]) {
                                    TempData["Status"] = false;
                                    TempData["Message"] = "This device has already been verified.";
                                    return RedirectToAction("Index", "Home");
                                }
                            }
                        }
                    } catch (Exception e) {
                        Debug.WriteLine(e.Message);
                    }

                    for (int i = 1; i < separated.Length; i++) {
                        if (separated[i].Length != 12) {
                            TempData["Status"] = false;
                            TempData["Message"] = "Invalid device found.";
                            return RedirectToAction("Index", "Home");
                        }
                        device dev = new device {
                            id = Guid.NewGuid(),
                            device_mac = separated[i].ToString(),
                            user_id = thisUser.id
                        };
                        entity.devices.Add(dev);
                    }
                    entity.SaveChanges();
                    TempData["Status"] = true;
                    TempData["Message"] = "Device successfully verified.";
                } else {
                    TempData["Status"] = false;
                    TempData["Message"] = "An error occurred when verifying this device, please try again.";
                }
                return View();
            }
        }

        /// <summary>
        /// Method sends a verification email to a user given their email address and a uniquely
        /// generated activation code. Used in the registration method.
        /// </summary>
        /// <param name="emailAddress">string value representing the full email address of the user</param>
        /// <param name="activationCode">string representation of the activation code GUID</param>
        [NonAction]
        public void SendRegistrationVerificationEmail(string emailAddress, string activationCode) {
            string verificationURL = "/User/VerifyAccount/" + activationCode;
            string link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verificationURL);

			
			MailAddress fromEmail = new MailAddress("youraddress@yourdomain", "Your Name");
            MailAddress toEmail = new MailAddress(emailAddress);

			//Make sure to encrypt your web.config file if you end up hosting anything!
			var fromEmailPassword = ConfigurationManager.AppSettings["emailServicePassword"];

            //Set up our SMTP client that facilitates the sending of our email
            SmtpClient smtp = new SmtpClient {
                Host = "smtp.yourhost.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };
            
            //Craft our message to verify this user.
            using (var message = new MailMessage(fromEmail, toEmail) {
                Subject = "Two Factor Authentication App - Account Creation",
                Body = "<br/><br/>Your Two Factor Authentication account has been" +
                        " successfully created. Please click on the below link to verify your account" +
                        " <br/><br/><a href='" + link + "'>" + link + "</a> ",

                IsBodyHtml = true
            })
                smtp.Send(message);
        }

        /// <summary>
        /// Method functionally similar to user verification email method, but also appends the mac addresses
        /// of each device to the activation link, and creates a slightly different email.
        /// </summary>
        /// <param name="emailAddress">string value of the email address to send to</param>
        /// <param name="devices">List of string values containing the mac addresses to verify</param>
        /// <param name="verificationCode">unique activation code for the user</param>
        [NonAction]
        public void SendDeviceVerificationEmail(string emailAddress, List<string> devices, string verificationCode) {
            string deviceNames = "";
            foreach(string dev in devices) {
                deviceNames = deviceNames + "_" + dev;
            }
            string verificationURL = "/User/VerifyDevice/" + verificationCode + "_" + deviceNames;
            string link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verificationURL);

            MailAddress fromEmail = new MailAddress("youraddress@yourdomain", "Your Name");
            MailAddress toEmail = new MailAddress(emailAddress);

            var fromEmailPassword = ConfigurationManager.AppSettings["emailServicePassword"];

            //Set up our SMTP client that facilitates the sending of our email
            SmtpClient smtp = new SmtpClient {
                Host = "smtp.yourhost.com",
                Port = 587, //standard port for outgoing emails.
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            //Craft our verification message to add a device.
            using (MailMessage message = new MailMessage(fromEmail, toEmail) {
                Subject = "Two Factor Authentication - Device Verification",
                Body = "<br/><br/>A login from a new device has been detected on your account." +
                       "Please verify that this is you by clicking the link below. Alternatively do NOT click " +
                       "the link if this was not you!<br/><br/><a href='" + link + "'>" + link + "</a> ",

            IsBodyHtml = true
            })
                smtp.Send(message);
        }

        /// <summary>
        /// Method returns the current network devices found on this machine.
        /// </summary>
        /// <returns>List<string> network device mac addresses in string format.</returns>
        public static List<string> GetDevices() {
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            List<string> mac_addresses = new List<string>();

            //A device can have multiple network adapters, so get them all.
            foreach (NetworkInterface adapter in nics) {
                string mac = adapter.GetPhysicalAddress().ToString();

                //Some devices aren't always operational,
                // so don't return their mac address.
                if (!String.IsNullOrEmpty(mac)) {
                    mac_addresses.Add(mac);
                }
            }

            return mac_addresses;
        }
    }
}