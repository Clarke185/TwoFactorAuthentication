# TwoFactorAuthentication
Repository stores a demonstration application for a simple Two Factor Authentication app. Please take the time to read the README.

----
Files:

SQL - The SQL scripts necessary to create the database and tables in SSMS are in this folder.

Template - A full template of the project exists in this folder, this can be used to create a new project in Visual Studio with this project as a "template". This is the preferred way for setting up an application to build, run, and test! Once done, you can view the source code within.

----
Prelim:

An entity data model also exists in the project, however this is simply set up for my local host, as such you will need to delete and reestablish this link to your own SQL Server Database. I have left this in for the sake of completeness.

You will need to create your own email address to send your authentication emails from. I recommend setting up a new email address to do this. Areas of changing are in:
- Web.config: App Settings
- UserController: "SendRegistrationVerificationEmail" and "SendDeviceVerificationEmail" methods. Read through these methods to find the relevant code to change, it should be fairly obvious.

You will also need to download and update the required NuGet packages. If you import from template, this should be a relatively straight-forward process.

IMPORTANT! Please do not use this application for production-ready work without scrutinizing and testing it first! This was in no way intended to function as a production application, and simply for the purposes of demonstrating Two Factor Authentication capabilities. If you decide to publish an application, at the very least you should encrypt your web.config file to prevent sensitive information being displayed in plaintext. Also, don't use a MAC address as you're second form of authentication, they rarely work for client (and will end up pulling the server MAC), and they're easily spoofable. Use Client SSL Certificates instead.

I'll be happy to answer any questions or queries via jamesmichaelclarke@hotmail.co.uk

Changelog:

09/07/2020 16:37 - Added raw C# code to application for completeness.
