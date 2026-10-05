using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

public interface IAuthService
{
    Task<AuthResponse?> LoginAsync(LoginRequest request);
    Task<(bool Success, string Message, User? User)> RegisterAsync(RegisterRequest request);
    Task<User?> GetUserByIdAsync(int userId);
}

public class AuthService : IAuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly IInputValidationService _validator;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        AppDbContext context,
        IConfiguration configuration,
        IInputValidationService validator,
        ILogger<AuthService> logger)
    {
        _context = context;
        _configuration = configuration;
        _validator = validator;
        _logger = logger;
    }

    public async Task<AuthResponse?> LoginAsync(LoginRequest request)
    {
        // Input validation
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            _logger.LogWarning("Login attempt with empty credentials");
            return null;
        }

        // Detect potential injection attempts (logging only)
        if (_validator.ContainsSqlInjectionRisk(request.Username))
        {
            _logger.LogWarning("Potential SQL injection attempt in username: {Username}", 
                _validator.SanitizeForDisplay(request.Username));
            return null;
        }

        // SECURE: Use parameterized query via EF Core (no string concatenation)
        var user = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Username == request.Username && u.IsActive);

        if (user == null)
        {
            // Constant-time delay to prevent timing attacks (simplified)
            await Task.Delay(100);
            _logger.LogWarning("Failed login for non-existent user");
            return null;
        }

        // Verify password with BCrypt (secure hashing)
        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("Failed login for user {Username}", user.Username);
            return null;
        }

        var token = GenerateJwtToken(user);
        var expires = DateTime.UtcNow.AddHours(1);

        _logger.LogInformation("Successful login for user {Username} with role {Role}", 
            user.Username, user.Role);

        return new AuthResponse
        {
            Token = token,
            Username = user.Username,
            Role = user.Role,
            ExpiresAt = expires
        };
    }

    public async Task<(bool Success, string Message, User? User)> RegisterAsync(RegisterRequest request)
    {
        // Validate inputs
        if (!_validator.IsValidUsername(request.Username))
            return (false, "Invalid username format.", null);

        if (!_validator.IsValidEmail(request.Email))
            return (false, "Invalid email format.", null);

        if (_validator.ContainsSqlInjectionRisk(request.Username) ||
            _validator.ContainsSqlInjectionRisk(request.Email))
        {
            _logger.LogWarning("Registration blocked due to potential injection");
            return (false, "Invalid input detected.", null);
        }

        // Check uniqueness with parameterized queries
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return (false, "Username already exists.", null);

        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            return (false, "Email already registered.", null);

        var user = new User
        {
            Username = _validator.SanitizeForStorage(request.Username),
            Email = _validator.SanitizeForStorage(request.Email),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password), // Secure hashing
            Role = "User", // Default role - RBAC
            IsActive = true
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("New user registered: {Username}", user.Username);
        return (true, "Registration successful.", user);
    }

    public async Task<User?> GetUserByIdAsync(int userId)
    {
        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId && u.IsActive);
    }

    private string GenerateJwtToken(User user)
    {
        var key = Encoding.UTF8.GetBytes(
            _configuration["Jwt:Key"] ?? "SafeVaultSuperSecretKeyThatIsAtLeast32CharactersLong!");

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role), // Critical for RBAC
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"] ?? "SafeVault",
            audience: _configuration["Jwt:Audience"] ?? "SafeVaultUsers",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
