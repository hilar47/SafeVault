using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Services;

public interface IInputValidationService
{
    bool IsValidUsername(string username);
    bool IsValidEmail(string email);
    bool ContainsSqlInjectionRisk(string input);
    bool ContainsXssRisk(string input);
    string SanitizeForDisplay(string input);
    string SanitizeForStorage(string input);
}

/// <summary>
/// Secure input validation service.
/// Demonstrates defense-in-depth against SQL Injection and XSS.
/// </summary>
public class InputValidationService : IInputValidationService
{
    // Common SQL injection patterns (for detection/logging - never rely solely on this)
    private static readonly Regex SqlInjectionPattern = new(
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE|DECLARE)\b)|(--)|(/\*)|(\*/)|(;)|(')|(\bOR\b.*=.*)|(\bAND\b.*=.*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // XSS patterns
    private static readonly Regex XssPattern = new(
        @"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|javascript:|on\w+\s*=|<iframe|<object|<embed|<link|<meta",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UsernamePattern = new(@"^[a-zA-Z0-9_]{3,50}$", RegexOptions.Compiled);
    private static readonly Regex EmailPattern = new(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

    public bool IsValidUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;
        return UsernamePattern.IsMatch(username);
    }

    public bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;
        return EmailPattern.IsMatch(email) && email.Length <= 100;
    }

    /// <summary>
    /// Detects potential SQL injection attempts for logging/alerting.
    /// IMPORTANT: This is NOT a substitute for parameterized queries.
    /// Always use parameterized queries / ORM for actual protection.
    /// </summary>
    public bool ContainsSqlInjectionRisk(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;
        return SqlInjectionPattern.IsMatch(input);
    }

    /// <summary>
    /// Detects potential XSS payloads.
    /// </summary>
    public bool ContainsXssRisk(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;
        return XssPattern.IsMatch(input);
    }

    /// <summary>
    /// Sanitize for safe HTML display (output encoding).
    /// Use this when rendering user content in HTML.
    /// </summary>
    public string SanitizeForDisplay(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        return HttpUtility.HtmlEncode(input);
    }

    /// <summary>
    /// Basic sanitization before storage.
    /// Prefer allowing most content and encoding on output (context-aware).
    /// </summary>
    public string SanitizeForStorage(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // Remove null bytes and control characters (except common whitespace)
        var cleaned = new string(input.Where(c =>
            c == '\n' || c == '\r' || c == '\t' || !char.IsControl(c)).ToArray());

        return cleaned.Trim();
    }
}
