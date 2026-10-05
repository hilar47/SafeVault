using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

public interface IVaultService
{
    Task<IEnumerable<VaultItem>> GetItemsForUserAsync(int userId, string role);
    Task<VaultItem?> GetItemByIdAsync(int itemId, int userId, string role);
    Task<VaultItem?> CreateItemAsync(CreateVaultItemRequest request, int ownerId);
    Task<VaultItem?> UpdateItemAsync(int itemId, UpdateVaultItemRequest request, int userId, string role);
    Task<bool> DeleteItemAsync(int itemId, int userId, string role);
}

/// <summary>
/// Secure vault service with RBAC and parameterized queries.
/// </summary>
public class VaultService : IVaultService
{
    private readonly AppDbContext _context;
    private readonly IInputValidationService _validator;
    private readonly ILogger<VaultService> _logger;

    public VaultService(
        AppDbContext context,
        IInputValidationService validator,
        ILogger<VaultService> logger)
    {
        _context = context;
        _validator = validator;
        _logger = logger;
    }

    public async Task<IEnumerable<VaultItem>> GetItemsForUserAsync(int userId, string role)
    {
        // RBAC: Admins see all, Users/Viewers see only their own
        IQueryable<VaultItem> query = _context.VaultItems.AsNoTracking();

        if (role != "Admin")
        {
            query = query.Where(v => v.OwnerId == userId);
        }

        return await query.OrderByDescending(v => v.CreatedAt).ToListAsync();
    }

    public async Task<VaultItem?> GetItemByIdAsync(int itemId, int userId, string role)
    {
        // SECURE parameterized lookup
        var item = await _context.VaultItems
            .AsNoTracking()
            .FirstOrDefaultAsync(v => v.Id == itemId);

        if (item == null)
            return null;

        // Authorization check (RBAC + ownership)
        if (role != "Admin" && item.OwnerId != userId)
        {
            _logger.LogWarning("Unauthorized access attempt to item {ItemId} by user {UserId}", itemId, userId);
            return null;
        }

        // Additional check for sensitive items
        if (item.IsSensitive && role == "Viewer")
        {
            _logger.LogWarning("Viewer attempted to access sensitive item {ItemId}", itemId);
            return null;
        }

        return item;
    }

    public async Task<VaultItem?> CreateItemAsync(CreateVaultItemRequest request, int ownerId)
    {
        // Validate for XSS risks
        if (_validator.ContainsXssRisk(request.Title) || _validator.ContainsXssRisk(request.Content))
        {
            _logger.LogWarning("XSS risk detected in vault item creation by user {UserId}", ownerId);
            // Still sanitize rather than reject, or reject based on policy
        }

        var item = new VaultItem
        {
            Title = _validator.SanitizeForStorage(request.Title),
            Content = _validator.SanitizeForStorage(request.Content),
            OwnerId = ownerId,
            IsSensitive = request.IsSensitive,
            CreatedAt = DateTime.UtcNow
        };

        _context.VaultItems.Add(item);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Vault item {ItemId} created by user {UserId}", item.Id, ownerId);
        return item;
    }

    public async Task<VaultItem?> UpdateItemAsync(int itemId, UpdateVaultItemRequest request, int userId, string role)
    {
        var item = await _context.VaultItems.FirstOrDefaultAsync(v => v.Id == itemId);

        if (item == null)
            return null;

        // Authorization: only owner or admin
        if (role != "Admin" && item.OwnerId != userId)
        {
            _logger.LogWarning("Unauthorized update attempt on item {ItemId}", itemId);
            return null;
        }

        if (request.Title != null)
        {
            if (_validator.ContainsXssRisk(request.Title))
                _logger.LogWarning("XSS risk in title update");
            item.Title = _validator.SanitizeForStorage(request.Title);
        }

        if (request.Content != null)
        {
            if (_validator.ContainsXssRisk(request.Content))
                _logger.LogWarning("XSS risk in content update");
            item.Content = _validator.SanitizeForStorage(request.Content);
        }

        if (request.IsSensitive.HasValue)
            item.IsSensitive = request.IsSensitive.Value;

        item.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return item;
    }

    public async Task<bool> DeleteItemAsync(int itemId, int userId, string role)
    {
        var item = await _context.VaultItems.FirstOrDefaultAsync(v => v.Id == itemId);

        if (item == null)
            return false;

        // Only owner or admin can delete
        if (role != "Admin" && item.OwnerId != userId)
        {
            _logger.LogWarning("Unauthorized delete attempt on item {ItemId}", itemId);
            return false;
        }

        _context.VaultItems.Remove(item);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Vault item {ItemId} deleted by user {UserId}", itemId, userId);
        return true;
    }
}
