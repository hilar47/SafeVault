using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
    public DbSet<VaultItem> VaultItems { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Role).HasMaxLength(20);
        });

        modelBuilder.Entity<VaultItem>(entity =>
        {
            entity.HasOne(v => v.Owner)
                  .WithMany()
                  .HasForeignKey(v => v.OwnerId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
