using TANE.Auth.Api.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection.Emit;

namespace TANE.Auth.Api.Context
{
    public class DataContext : IdentityDbContext<ApplicationUser>
    {

        public DataContext(DbContextOptions options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            string adminRoleId = Guid.NewGuid().ToString();
            string userRoleId = Guid.NewGuid().ToString();

            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole { Id = adminRoleId, Name = "Admin", NormalizedName = "ADMIN".ToUpper(), ConcurrencyStamp = Guid.NewGuid().ToString() },
                new IdentityRole { Id = userRoleId, Name = "User", NormalizedName = "USER".ToUpper(), ConcurrencyStamp = Guid.NewGuid().ToString() }
            );

            //Add admin user
            string userId = Guid.NewGuid().ToString();
            string username = "Admin";
            string email = "Admin";

            var user = new ApplicationUser
            {
                Id = userId,
                UserName = username,
                NormalizedUserName = username.ToUpper(),
                Email = email,
                NormalizedEmail = email.ToUpper(),
                EmailConfirmed = true,
                ConcurrencyStamp = Guid.NewGuid().ToString()
            };

            //Hash the password for admin user
            PasswordHasher<ApplicationUser> ph = new PasswordHasher<ApplicationUser>();

            user.PasswordHash = ph.HashPassword(user, "Admin");

            //seed admin user
            modelBuilder.Entity<ApplicationUser>().HasData(user);

            //Add admin to admin role
            var adminRole = new IdentityUserRole<string>
            {
                RoleId = adminRoleId,
                UserId = userId
            };

            //Add admin to user role
            var userRole = new IdentityUserRole<string>
            {
                RoleId = userRoleId,
                UserId = userId
            };

            //Seed roles to admin user
            modelBuilder.Entity<IdentityUserRole<string>>().HasData(adminRole);
            modelBuilder.Entity<IdentityUserRole<string>>().HasData(userRole);

            //Add test user
            string user1Id = Guid.NewGuid().ToString();
            string username1 = "Test";
            string email1 = "Test";

            var user1 = new ApplicationUser
            {
                Id = user1Id,
                UserName = username1,
                NormalizedUserName = username1.ToUpper(),
                Email = email1,
                NormalizedEmail = email1.ToUpper(),
                EmailConfirmed = true,
                ConcurrencyStamp = Guid.NewGuid().ToString()
            };

            //Hash the password for test user
            user1.PasswordHash = ph.HashPassword(user1, "Test1234!");

            //seed test user
            modelBuilder.Entity<ApplicationUser>().HasData(user1);

            //Add test to user role
            var userRole1 = new IdentityUserRole<string>
            {
                RoleId = userRoleId,
                UserId = user1Id
            };

            //Seed roles to test user
            modelBuilder.Entity<IdentityUserRole<string>>().HasData(userRole1);
        }
    }
}
