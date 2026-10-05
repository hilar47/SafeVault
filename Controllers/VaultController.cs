using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize] // All endpoints require authentication
public class VaultController : ControllerBase
{
    private readonly IVaultService _vaultService;
    private readonly IInputValidationService _validator;
    private readonly ILogger<VaultController> _logger;

    public VaultController(
        IVaultService vaultService,
        IInputValidationService validator,
        ILogger<VaultController> logger)
    {
        _vaultService = vaultService;
        _validator = validator;
        _logger = logger;
    }

    private (int UserId, string Role) GetCurrentUser()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value ?? "User";
        var userId = int.TryParse(userIdClaim, out var id) ? id : 0;
        return (userId, role);
    }

    /// <summary>
    /// Get vault items. RBAC applied: Admin sees all, others see only own.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "VaultAccess")]
    public async Task<IActionResult> GetItems()
    {
        var (userId, role) = GetCurrentUser();
        var items = await _vaultService.GetItemsForUserAsync(userId, role);

        // Output encoding for XSS prevention when returning to client
        var safeItems = items.Select(i => new
        {
            i.Id,
            Title = _validator.SanitizeForDisplay(i.Title),
            Content = _validator.SanitizeForDisplay(i.Content),
            i.IsSensitive,
            i.CreatedAt,
            i.UpdatedAt,
            i.OwnerId
        });

        return Ok(safeItems);
    }

    /// <summary>
    /// Get single item by ID with ownership/RBAC check.
    /// </summary>
    [HttpGet("{id:int}")]
    [Authorize(Policy = "VaultAccess")]
    public async Task<IActionResult> GetItem(int id)
    {
        var (userId, role) = GetCurrentUser();
        var item = await _vaultService.GetItemByIdAsync(id, userId, role);

        if (item == null)
            return NotFound(new { error = "Item not found or access denied." });

        return Ok(new
        {
            item.Id,
            Title = _validator.SanitizeForDisplay(item.Title),
            Content = _validator.SanitizeForDisplay(item.Content),
            item.IsSensitive,
            item.CreatedAt,
            item.UpdatedAt,
            item.OwnerId
        });
    }

    /// <summary>
    /// Create a new vault item. Input validated against XSS/SQL risks.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "UserOrAdmin")]
    public async Task<IActionResult> CreateItem([FromBody] CreateVaultItemRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var (userId, _) = GetCurrentUser();
        var item = await _vaultService.CreateItemAsync(request, userId);

        if (item == null)
            return BadRequest(new { error = "Failed to create item." });

        return CreatedAtAction(nameof(GetItem), new { id = item.Id }, new
        {
            item.Id,
            Title = _validator.SanitizeForDisplay(item.Title),
            Content = _validator.SanitizeForDisplay(item.Content),
            item.IsSensitive
        });
    }

    /// <summary>
    /// Update an existing item. Only owner or Admin.
    /// </summary>
    [HttpPut("{id:int}")]
    [Authorize(Policy = "UserOrAdmin")]
    public async Task<IActionResult> UpdateItem(int id, [FromBody] UpdateVaultItemRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var (userId, role) = GetCurrentUser();
        var item = await _vaultService.UpdateItemAsync(id, request, userId, role);

        if (item == null)
            return NotFound(new { error = "Item not found or access denied." });

        return Ok(new
        {
            item.Id,
            Title = _validator.SanitizeForDisplay(item.Title),
            Content = _validator.SanitizeForDisplay(item.Content),
            item.IsSensitive
        });
    }

    /// <summary>
    /// Delete an item. Only owner or Admin. Admin-only for force deletes of others.
    /// </summary>
    [HttpDelete("{id:int}")]
    [Authorize(Policy = "UserOrAdmin")]
    public async Task<IActionResult> DeleteItem(int id)
    {
        var (userId, role) = GetCurrentUser();
        var success = await _vaultService.DeleteItemAsync(id, userId, role);

        if (!success)
            return NotFound(new { error = "Item not found or access denied." });

        return NoContent();
    }

    /// <summary>
    /// Admin-only endpoint demonstrating strict RBAC.
    /// </summary>
    [HttpGet("admin/all")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> GetAllItemsAdmin()
    {
        var (userId, role) = GetCurrentUser();
        var items = await _vaultService.GetItemsForUserAsync(userId, role); // role=Admin returns all

        return Ok(items.Select(i => new
        {
            i.Id,
            Title = _validator.SanitizeForDisplay(i.Title),
            Content = _validator.SanitizeForDisplay(i.Content),
            i.OwnerId,
            i.IsSensitive,
            i.CreatedAt
        }));
    }
}
