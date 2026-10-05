using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public class VaultItem
{
    public int Id { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 1)]
    // Prevent XSS: no HTML tags allowed
    [RegularExpression(@"^[^<>]*$", ErrorMessage = "Title cannot contain HTML tags.")]
    public string Title { get; set; } = string.Empty;

    [Required]
    [StringLength(1000)]
    // Content is stored safely; XSS prevented on output via encoding
    public string Content { get; set; } = string.Empty;

    public int OwnerId { get; set; }
    public User? Owner { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    public bool IsSensitive { get; set; } = false;
}

public class CreateVaultItemRequest
{
    [Required]
    [StringLength(100, MinimumLength = 1)]
    [RegularExpression(@"^[^<>]*$", ErrorMessage = "Title cannot contain HTML tags.")]
    public string Title { get; set; } = string.Empty;

    [Required]
    [StringLength(1000)]
    public string Content { get; set; } = string.Empty;

    public bool IsSensitive { get; set; } = false;
}

public class UpdateVaultItemRequest
{
    [StringLength(100, MinimumLength = 1)]
    [RegularExpression(@"^[^<>]*$", ErrorMessage = "Title cannot contain HTML tags.")]
    public string? Title { get; set; }

    [StringLength(1000)]
    public string? Content { get; set; }

    public bool? IsSensitive { get; set; }
}
