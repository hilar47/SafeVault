using SafeVault.Models;

namespace SafeVault.Data;

public static class SeedData
{
    public static void Initialize(AppDbContext context)
    {
        if (context.Users.Any())
            return;

        // Pre-hashed passwords using BCrypt (password: Admin@123, User@123)
        var admin = new User
        {
            Username = "admin",
            Email = "admin@safevault.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@123"),
            Role = "Admin",
            IsActive = true
        };

        var user = new User
        {
            Username = "demo_user",
            Email = "user@safevault.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("User@123"),
            Role = "User",
            IsActive = true
        };

        var viewer = new User
        {
            Username = "viewer",
            Email = "viewer@safevault.local",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Viewer@123"),
            Role = "Viewer",
            IsActive = true
        };

        context.Users.AddRange(admin, user, viewer);
        context.SaveChanges();

        // Sample vault items
        context.VaultItems.AddRange(
            new VaultItem
            {
                Title = "Welcome Note",
                Content = "This is a secure vault item. Content is protected against XSS.",
                OwnerId = user.Id,
                IsSensitive = false
            },
            new VaultItem
            {
                Title = "Admin Secrets",
                Content = "Only admins and owners can access sensitive items.",
                OwnerId = admin.Id,
                IsSensitive = true
            }
        );
        context.SaveChanges();
    }
}
