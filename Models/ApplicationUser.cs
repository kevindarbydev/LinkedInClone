using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace LinkedInClone.Models
{


    public class ApplicationUser : IdentityUser
    {

        [DataType(DataType.Date)]
        public DateTime CreatedDate { get; set; } = DateTime.Now;

        // public ICollection<Connection> SentConnections { get; set; }

        // public ICollection<Connection> ReceivedConnections { get; set; }

        public string RoleId { get; set; }
        //  public virtual IdentityRole Role { get; set; }


        public string Company { get; set; }

        public string FullName { get; set; }

    }
}