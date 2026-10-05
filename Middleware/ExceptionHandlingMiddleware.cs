using System.Net;
using System.Text.Json;

namespace SafeVault.Middleware;

/// <summary>
/// Global exception handler - prevents leaking sensitive information.
/// </summary>
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception occurred");
            await HandleExceptionAsync(context, ex);
        }
    }

    private static Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

        // NEVER expose stack traces or internal details in production
        var response = new
        {
            error = "An unexpected error occurred. Please try again later.",
            // Only include details in development
            detail = context.RequestServices.GetService<IWebHostEnvironment>()?.IsDevelopment() == true
                ? exception.Message
                : null
        };

        var json = JsonSerializer.Serialize(response);
        return context.Response.WriteAsync(json);
    }
}
