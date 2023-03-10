using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using LinkedInClone.Data;
using LinkedInClone.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using LinkedInClone.Services;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Diagnostics;

namespace LinkedInClone.Controllers
{
    [Authorize(Roles = "User")]
    public class JobApplicationsController : Controller
    {
        private readonly AppDbContext _context;
        private readonly ILogger _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IBlobService _blobService;
        private readonly IEmailSender _emailSender;

        public JobApplicationsController(AppDbContext context, ILogger<JobPosting> logger, UserManager<ApplicationUser> userManager,
         IBlobService blobService, IEmailSender emailSender)
        {
            _context = context;
            _logger = logger;
            _userManager = userManager;
            _blobService = blobService;
            _emailSender = emailSender;
        }

        // GET: All Job Applications for logged in user only
        public async Task<IActionResult> UserApplications()
        {
            return View(await _context.JobApplications.Include("Job").Where(ja => ja.Applicant.Id == HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value).ToListAsync());
        }

        // GET: All JobPostings
        public async Task<IActionResult> AllAvailableJobs()
        {
            return View(await _context.JobPostings.Include("Recruiter").ToListAsync());
        }

        // GET: JobApplications/Create
        public IActionResult Create(int id)
        {
            var numOfApplications = _context.JobApplications.Where(ja => (ja.Job.Id == id && ja.Applicant.Id == HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value)).Count();
            if (numOfApplications > 0)
            {
                TempData["generalInfo"] = $"Sorry {User.Identity.Name}, you have already applied for this job!";
                return RedirectToAction(nameof(AllAvailableJobs));
            }
            var job = _context.JobPostings.Where(jobPost => jobPost.Id == id).FirstOrDefault();
            ViewData["jobTitle"] = job.JobTitle;
            return View();
        }

        // POST: JobApplications/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(int id, [Bind("Id,FilePath,FileName,CreatedDate")] JobApplication jobApplication)
        {
            ModelState.Remove("Applicant");
            ModelState.Remove("Job");
            jobApplication.Applicant = await _userManager.GetUserAsync(User);
            jobApplication.Job = await _context.JobPostings.Where(jp => jp.Id == id).FirstOrDefaultAsync();

            if (ModelState.IsValid)
            {
                if (jobApplication.FileName == null)
                {
                    TempData["generalInfo"] = $"Sorry {User.Identity.Name}, you can't apply without uploading your CV!";
                    return View();
                }


                if (jobApplication.FileName != null)
                {
                    var downloadedData = await _blobService.GetBlobAsync($"https://fsd05regex.blob.core.windows.net/blob-storage/{jobApplication.FileName}");

                    if (downloadedData == null)
                    {
                        jobApplication.FilePath = @$"wwwroot/Documents/{jobApplication.FileName}";
                        await _blobService.UploadFileBlobAsync(jobApplication.FilePath, jobApplication.FileName);

                        _logger.LogInformation(string.Empty, "File has been uploaded successfully to Blob.");
                    }
                }

                // find number of applications for chosen job 
                int numOfApplications = await _context.JobApplications
                    .Where(ja => (ja.Job.Id == jobApplication.Job.Id && ja.Applicant.Id == HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value))
                    .CountAsync();

                // redirect to all available jobs if user has already applied for chosen job (without saving to DB)
                if (numOfApplications > 0)
                {
                    TempData["generalInfo"] = $"Sorry {User.Identity.Name}! You've already applied for this job";
                    return RedirectToAction(nameof(AllAvailableJobs));
                }

                _context.Add(jobApplication);
                await _context.SaveChangesAsync();

                //Couldnt get Recruiter Id from JobPosting obj

                //Send emails upon successful application
                // Retrieve the user's email address
                // try{
                // var user = jobApplication.Applicant;
                // var userEmail = user.Email;

                // // Retrieve the recruiter's email address
                // var jobPosting = await _context.JobPostings.Where(jp => jp.Id == id).FirstOrDefaultAsync();
                // Debug.WriteLine($" JP.R {jobPosting.Recruiter} JP.RID {jobPosting.RecruitId}");
                // var recruiter = await _context.AppUsers.FindAsync(jobPosting.Recruiter);

                // var recruiterEmail = recruiter.Email;

                // // Send an email to the recruiter
                // await _emailSender.SendEmailAsync(recruiterEmail, "New Job Application", $"A new job application has been submitted for your job posting: {jobPosting.JobTitle}. It now has {jobPosting.JobApplications.Count()} applicants.");
                // Console.WriteLine($"Notified recruiter {recruiter.FullName} of job posting application: {jobPosting.JobTitle}");

                // // Send an email to the user
                // await _emailSender.SendEmailAsync(userEmail, "Job Application Submited", $"Your job application for {jobPosting.JobTitle} has been submitted successfully.");
                // Console.WriteLine($"Notified user {jobApplication.Applicant.FullName} of their application to: {jobPosting.JobTitle}");
                // }
                // catch (Exception ex)
                // {
                //     Debug.WriteLine(ex.Message);
                // }
                return RedirectToAction(nameof(UserApplications));

            }
            return View(jobApplication);
        }

        // GET: JobApplications/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null || _context.JobApplications == null)
            {
                return NotFound();
            }

            var jobApplication = await _context.JobApplications.Include("Job")
                .FirstOrDefaultAsync(m => m.JobApplicationId == id);
            if (jobApplication == null)
            {
                return NotFound();
            }

            return View(jobApplication);
        }

        // POST: JobApplications/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (_context.JobApplications == null)
            {
                return Problem("Entity set 'AppDbContext.JobApplications'  is null.");
            }
            var jobApplication = await _context.JobApplications.FindAsync(id);
            if (jobApplication != null)
            {
                _context.JobApplications.Remove(jobApplication);
            }

            await _context.SaveChangesAsync();
            TempData["generalInfo"] = $"Deleted job application successfully!";
            return RedirectToAction(nameof(UserApplications));
        }

        private bool JobApplicationExists(int id)
        {
            return _context.JobApplications.Any(e => e.JobApplicationId == id);
        }
    }
}
