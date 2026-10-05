using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Security-focused integration tests demonstrating verification of:
/// - SQL Injection prevention
/// - XSS prevention
/// - Authentication & Authorization (RBAC)
/// - Input validation
/// </summary>
public class SecurityTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public SecurityTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Ensure in-memory DB for tests
                var descriptor = services.SingleOrDefault(
                    d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
                if (descriptor != null)
                    services.Remove(descriptor);

                services.AddDbContext<AppDbContext>(options =>
                    options.UseInMemoryDatabase("TestDb_" + Guid.NewGuid()));
            });
        });
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsToken()
    {
        var request = new LoginRequest { Username = "admin", Password = "Admin@123" };
        var response = await _client.PostAsJsonAsync("/api/auth/login", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(content);
        Assert.False(string.IsNullOrEmpty(content.Token));
        Assert.Equal("Admin", content.Role);
    }

    [Fact]
    public async Task Login_WithInvalidCredentials_ReturnsUnauthorized()
    {
        var request = new LoginRequest { Username = "admin", Password = "WrongPassword!" };
        var response = await _client.PostAsJsonAsync("/api/auth/login", request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SqlInjection_InUsername_IsBlockedOrHarmless()
    {
        // Classic SQL injection payload
        var payloads = new[]
        {
            "admin' OR '1'='1",
            "admin'; DROP TABLE Users;--",
            "admin' UNION SELECT * FROM Users--"
        };

        foreach (var payload in payloads)
        {
            var request = new LoginRequest { Username = payload, Password = "anything" };
            var response = await _client.PostAsJsonAsync("/api/auth/login", request);

            // Should not succeed (no injection possible due to parameterized queries)
            Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task Xss_InVaultItemTitle_IsSanitizedOnOutput()
    {
        // First login as user
        var loginReq = new LoginRequest { Username = "demo_user", Password = "User@123" };
        var loginResp = await _client.PostAsJsonAsync("/api/auth/login", loginReq);
        var auth = await loginResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(auth);

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", auth.Token);

        // Attempt XSS payload
        var xssPayload = new CreateVaultItemRequest
        {
            Title = "<script>alert('XSS')</script>",
            Content = "Normal content with <img src=x onerror=alert(1)>"
        };

        var createResp = await _client.PostAsJsonAsync("/api/vault", xssPayload);
        // May succeed (we sanitize rather than always reject) or be validated
        // The key is that output is encoded

        if (createResp.IsSuccessStatusCode)
        {
            var created = await createResp.Content.ReadFromJsonAsync<JsonElement>();
            var title = created.GetProperty("title").GetString() ?? "";
            var content = created.GetProperty("content").GetString() ?? "";

            // Output should be HTML-encoded
            Assert.DoesNotContain("<script>", title);
            Assert.Contains("&lt;script&gt;", title); // Encoded
        }
    }

    [Fact]
    public async Task Unauthorized_Access_WithoutToken_Returns401()
    {
        var response = await _client.GetAsync("/api/vault");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rbac_Viewer_CannotCreateItems()
    {
        var loginReq = new LoginRequest { Username = "viewer", Password = "Viewer@123" };
        var loginResp = await _client.PostAsJsonAsync("/api/auth/login", loginReq);
        var auth = await loginResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(auth);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", auth.Token);

        var item = new CreateVaultItemRequest { Title = "Test", Content = "Test content" };
        var response = await client.PostAsJsonAsync("/api/vault", item);

        // Viewer role does not have UserOrAdmin policy
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Rbac_Admin_CanAccessAdminEndpoint()
    {
        var loginReq = new LoginRequest { Username = "admin", Password = "Admin@123" };
        var loginResp = await _client.PostAsJsonAsync("/api/auth/login", loginReq);
        var auth = await loginResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(auth);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", auth.Token);

        var response = await client.GetAsync("/api/vault/admin/all");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task InputValidation_WeakPassword_IsRejected()
    {
        var request = new RegisterRequest
        {
            Username = "newuser",
            Email = "new@test.com",
            Password = "weak" // Fails complexity requirements
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}

// Marker for WebApplicationFactory
public partial class Program { }
