# SafeVault - Secure .NET Web API Demo

A mock ASP.NET Core 8 Web API demonstrating secure coding practices for input validation, SQL injection prevention, authentication, authorization (RBAC), XSS mitigation, and security testing.

> **Note**: This is a **demo / educational mockup**. It uses an in-memory database and is not production-ready. Do not use the JWT secret or sample passwords in real applications.

## Features Demonstrated

### 1. Input Validation
- Data Annotations (`[Required]`, `[StringLength]`, `[RegularExpression]`, `[EmailAddress]`)
- Custom validation service detecting SQL injection and XSS patterns
- Password complexity enforcement
- Sanitization before storage

### 2. SQL Injection Prevention
- **Entity Framework Core** with parameterized queries (never string concatenation)
- `AsNoTracking()` for read operations
- Input risk detection for logging/alerting (defense-in-depth)
- No dynamic SQL anywhere in the codebase

### 3. Authentication
- JWT Bearer tokens
- Secure password hashing with **BCrypt**
- Claims-based identity (`NameIdentifier`, `Role`, etc.)
- Constant-time considerations on failed logins

### 4. Authorization & RBAC
- Role-based policies: `AdminOnly`, `UserOrAdmin`, `VaultAccess`
- Roles: `Admin`, `User`, `Viewer`
- Ownership checks + role checks in services
- Sensitive item protection (Viewers cannot access)

### 5. XSS Prevention
- HTML encoding on output (`HttpUtility.HtmlEncode`)
- Content-Security-Policy header
- X-XSS-Protection, X-Content-Type-Options, X-Frame-Options
- Input pattern detection for script tags / event handlers
- Regex preventing HTML tags in titles

### 6. Other Security Measures
- Security headers middleware
- Global exception handling (no stack trace leakage)
- Unique indexes on username/email
- Soft authorization failures (404 instead of revealing existence)

## Sample Users (seeded)

| Username   | Password    | Role   |
|------------|-------------|--------|
| admin      | Admin@123   | Admin  |
| demo_user  | User@123    | User   |
| viewer     | Viewer@123  | Viewer |

## API Endpoints

| Method | Endpoint                  | Auth          | Description                  |
|--------|---------------------------|---------------|------------------------------|
| POST   | /api/auth/register        | Anonymous     | Register new user            |
| POST   | /api/auth/login           | Anonymous     | Login, get JWT               |
| GET    | /api/auth/me              | Authenticated | Current user info            |
| GET    | /api/vault                | VaultAccess   | List items (RBAC filtered)   |
| GET    | /api/vault/{id}           | VaultAccess   | Get single item              |
| POST   | /api/vault                | UserOrAdmin   | Create item                  |
| PUT    | /api/vault/{id}           | UserOrAdmin   | Update item                  |
| DELETE | /api/vault/{id}           | UserOrAdmin   | Delete item                  |
| GET    | /api/vault/admin/all      | AdminOnly     | Admin list all items         |

## Running the Application

```bash
cd SafeVault
dotnet restore
dotnet run
```

Swagger UI: `https://localhost:5xxx/swagger` (or check console output)

## Running Tests

The `Tests/SecurityTests.cs` file contains integration tests covering:
- Valid / invalid login
- SQL injection payloads
- XSS payload sanitization
- Unauthorized access (401)
- RBAC enforcement (403 for Viewer creating items)
- Password complexity validation

To run properly, convert to a separate test project or use:

```bash
dotnet test
```

(Requires adding a test project reference if expanding.)

## Vulnerabilities Identified & Fixes Applied

### Originally Vulnerable Patterns (Hypothetical / Common Issues Fixed)

| Vulnerability              | Risk Level | How it Manifested                          | Fix Applied                                      | Copilot Assistance Role                          |
|----------------------------|------------|--------------------------------------------|--------------------------------------------------|--------------------------------------------------|
| SQL Injection              | Critical   | String concatenation in queries            | EF Core parameterized queries only               | Generated safe EF LINQ queries & warned against raw SQL |
| XSS (Stored / Reflected)   | High       | Raw output of user content                 | HTML encode on every response + CSP headers      | Suggested encoding helpers & CSP middleware      |
| Weak / Plaintext Passwords | Critical   | Storing passwords in clear text            | BCrypt hashing + complexity regex                | Recommended BCrypt.Net and complexity patterns   |
| Missing Authentication     | High       | Open endpoints                             | JWT + `[Authorize]` attributes                   | Scaffolded JWT auth configuration                |
| Broken Access Control      | High       | No role/ownership checks                   | RBAC policies + ownership in service layer       | Generated policy definitions and claim checks    |
| Information Disclosure     | Medium     | Stack traces / existence leaks             | Global exception middleware + 404 on auth fail   | Created safe error response patterns             |
| Clickjacking / MIME Sniff  | Medium     | Missing security headers                   | SecurityHeadersMiddleware                        | Provided header recommendations                  |

### How Copilot Assisted in the Debugging Process

1. **Code Generation**: Produced secure boilerplate for JWT setup, BCrypt integration, and EF Core models with proper indexes.
2. **Pattern Detection**: When reviewing hypothetical vulnerable code (e.g., `$"SELECT * FROM Users WHERE Username = '{input}'"`), Copilot flagged it and suggested parameterized alternatives.
3. **Validation Logic**: Generated robust regex patterns for username, email, password strength, and XSS/SQL risk detection.
4. **RBAC Implementation**: Helped define authorization policies and correctly place `[Authorize(Policy = "...")]` attributes plus service-level checks.
5. **Test Generation**: Created the security-focused integration tests covering injection payloads, role boundaries, and encoding verification.
6. **Header Hardening**: Suggested modern security headers (CSP, X-Frame-Options, etc.) and implemented them as middleware.
7. **Iterative Refinement**: During "debugging", Copilot helped ensure no sensitive data leaked in error responses and that Viewer role was properly restricted.

## Project Structure

```
SafeVault/
├── Controllers/
│   ├── AuthController.cs
│   └── VaultController.cs
├── Data/
│   ├── AppDbContext.cs
│   └── SeedData.cs
├── Middleware/
│   ├── ExceptionHandlingMiddleware.cs
│   └── SecurityHeadersMiddleware.cs
├── Models/
│   ├── User.cs
│   └── VaultItem.cs
├── Services/
│   ├── AuthService.cs
│   ├── InputValidationService.cs
│   └── VaultService.cs
├── Tests/
│   └── SecurityTests.cs
├── Program.cs
├── appsettings.json
├── SafeVault.csproj
└── README.md
```

## Security Best Practices Applied

- Defense in depth (validation + parameterization + encoding + headers)
- Least privilege (RBAC + ownership)
- Secure defaults (strong password policy, short-lived JWT)
- Fail securely (generic errors, no existence leakage)
- Logging of security-relevant events without logging secrets

---

**Disclaimer**: Educational purposes only. For production, use Azure Key Vault / proper secrets management, HTTPS only, rate limiting, account lockout, refresh tokens, audit logging, and regular dependency scanning.
