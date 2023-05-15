using LinkedInClone.Data;
using LinkedInClone.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace LinkedInClone.Controllers;
[Area("Account")]
public class AccountController : Controller
{
    private readonly ILogger<AccountController> _logger;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AppDbContext _db;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;


    public AccountController(ILogger<AccountController> logger, AppDbContext db, RoleManager<IdentityRole> roleManager, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
    {
        _logger = logger;
        _db = db;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _userManager = userManager;
        try
        {
            CreateRolesandUsers().Wait();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }


    [AllowAnonymous]
    [Route("/Account/GoogleLogin")]
    public IActionResult GoogleLogin()
    {
        string redirectUrl = Url.Action("GoogleResponse", "Account");
        var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
        return new ChallengeResult("Google", properties);
    }


    [AllowAnonymous]
    [Route("/Account/GoogleResponse")]
    public async Task<IActionResult> GoogleResponse()
    {
        ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();

        if (info == null)
            return View("ExternalLoginFailed");
        var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);

        string[] userInfo = { info.Principal.FindFirst(ClaimTypes.Name).Value, info.Principal.FindFirst(ClaimTypes.Email).Value };
        if (result.Succeeded)
        {
            _logger.LogInformation($"User {userInfo[0]} signed in successfully using google.");
            return RedirectToAction("Index", "Home");
        }
        else
        {
            var user = await _userManager.FindByEmailAsync(info.Principal.FindFirst(ClaimTypes.Email).Value);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    Email = info.Principal.FindFirst(ClaimTypes.Email).Value,
                    UserName = info.Principal.FindFirst(ClaimTypes.Email).Value,
                    FullName = info.Principal.FindFirst(ClaimTypes.Name).Value
                };

                IdentityResult identResult = await _userManager.CreateAsync(user);
                foreach (var error in identResult.Errors)
                {
                    _logger.LogInformation($"Create Async result -> {error.Description}");
                }
                if (identResult.Succeeded)
                {
                    identResult = await _userManager.AddLoginAsync(user, info);
                    if (identResult.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                        _logger.LogInformation($"Google login information added for user {userInfo[0]}");
                        await _signInManager.SignInAsync(user, false);
                        return RedirectToAction("Index", "Home");
                    }
                }
            }
            else
            {
                var identResult = await _userManager.AddLoginAsync(user, info);
                if (identResult.Succeeded)
                {
                    await _signInManager.SignInAsync(user, false);
                    return RedirectToAction("Index", "Home");
                }
            }
            return AccessDenied();
        }
    }

    [HttpDelete("/Account/DeleteUser/{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            Console.WriteLine($"User with ID:{id} does not exist!");
            return NotFound();
        }
        var result = await _userManager.DeleteAsync(user);
        if (result.Succeeded)
        {
            Console.WriteLine("User deleted successfully!");
            return RedirectToAction("AdminPanel", "Home");
        }
        return BadRequest();
    }

    [HttpPost("/Account/UpdateUser/{id}")]
    public async Task<IActionResult> UpdateUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            Debug.WriteLine($"User with ID:{id} does not exist!");
            return NotFound();
        }
        Debug.WriteLine($"Found user {user.Email} , {user.FullName} \n FOUND VALUES IN FORM : {Request.Form["FullName"]} , {Request.Form["Email"]} ");

        user.FullName = Request.Form["FullName"];
        user.Email = Request.Form["Email"];
        user.UserName = Request.Form["Email"];
        Debug.WriteLine($"user after update {user.Email} , {user.FullName}");

        var result = await _userManager.UpdateAsync(user);
        if (result.Succeeded)
        {
            // Redirect the user to the updated user information page
            return RedirectToAction("MyAccount", "Home");
        }
        else
        {
            return View("Error");
        }
    }

    private async Task CreateRolesandUsers()
    {
        bool x = await _roleManager.RoleExistsAsync("Admin");
        if (!x)
        {
            // first we create Admin rool    
            var role = new IdentityRole();
            role.Name = "Admin";
            await _roleManager.CreateAsync(role);

            //Here we create a Admin super user who will maintain the website                   

            var user = new ApplicationUser();
            user.UserName = "kevindarbydev@gmail.com";
            user.Email = "kevindarbydev@gmail.com";

            string userPWD = "GoodPW123!";

            IdentityResult chkUser = await _userManager.CreateAsync(user, userPWD);

            //Add default User to Role Admin    
            if (chkUser.Succeeded)
            {
                var result1 = await _userManager.AddToRoleAsync(user, "Admin");
            }
        }

        // creating Creating User role     
        x = await _roleManager.RoleExistsAsync("User");
        if (!x)
        {
            var role = new IdentityRole();
            role.Name = "User";
            await _roleManager.CreateAsync(role);
        }

        // creating Creating Recruiter role     
        x = await _roleManager.RoleExistsAsync("Recruiter");
        if (!x)
        {
            var role = new IdentityRole();
            role.Name = "Recruiter";
            await _roleManager.CreateAsync(role);
        }
    }

    public IActionResult AccessDenied()
    {
        return View();
    }
}
