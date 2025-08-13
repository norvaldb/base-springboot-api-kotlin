# Copilot Instructions: Kotlin Spring Boot API

## Technology Stack
- **Language**: Kotlin
- **Framework**: Spring Boot 3.x
- **Build Tool**: Maven
- **Database**: Oracle (containerized for development)
- **Architecture**: RESTful API following SOLID principles

## SOLID Principles Implementation

### Single Responsibility Principle (SRP)
- One class = one responsibility
- Separate controllers, services, repositories, and DTOs
- Use `@Component`, `@Service`, `@Repository` annotations appropriately

### Open/Closed Principle (OCP)
- Use interfaces for services and repositories
- Prefer composition over inheritance
- Implement strategy pattern for varying behaviors

### Liskov Substitution Principle (LSP)
- All implementations must honor interface contracts
- Use proper inheritance hierarchies
- Avoid breaking base class behavior

### Interface Segregation Principle (ISP)
- Create focused, specific interfaces
- Avoid fat interfaces with unused methods
- Use multiple small interfaces over one large interface

### Dependency Inversion Principle (DIP)
- Depend on abstractions, not concretions
- Use constructor injection with `@Autowired`
- Program against interfaces

## Code Structure

```
src/main/kotlin/
├── controller/     # REST endpoints (@RestController)
├── service/        # Business logic interfaces and implementations
├── repository/     # Data access layer (@Repository)
├── model/          # Entity classes (@Entity)
├── dto/            # Data Transfer Objects
├── config/         # Configuration classes (@Configuration)
└── exception/      # Custom exceptions and handlers
```

## Coding Standards

### Naming Conventions
- Classes: PascalCase (`UserService`)
- Functions: camelCase (`findUserById`)
- Constants: UPPER_SNAKE_CASE (`MAX_RETRY_COUNT`)
- Packages: lowercase (`com.example.service`)

### Spring Boot Best Practices
- Use `@RestController` for REST endpoints
- Use `@Service` for business logic
- Use `@Repository` for data access
- Use `@Configuration` for beans
- Prefer constructor injection
- Use `@Valid` for request validation
- Return `ResponseEntity<T>` from controllers

### Kotlin Specifics
- Use data classes for DTOs and entities
- Leverage null safety (`?`, `!!`, `?.`)
- Use extension functions when appropriate
- Prefer `val` over `var`
- Use sealed classes for result types

### Error Handling
- Use `@ControllerAdvice` for global exception handling
- Create custom exceptions extending appropriate base classes
- Return proper HTTP status codes
- Include meaningful error messages

### Testing
- Use Kotlin Test (Kotest) with MockK for idiomatic Kotlin testing
- Integration tests with `@SpringBootTest`
- Use `@MockBean` for Spring context mocking
- Test all service layer logic
- Use TestContainers with Oracle XE for database integration tests
- Use `shouldBe`, `shouldThrow`, `shouldNotBe` for assertions

### API Documentation
- Use OpenAPI 3.0 with SpringDoc OpenAPI for automatic documentation
- Add comprehensive `@Operation`, `@Parameter`, and `@Schema` annotations
- Document all error responses with `@ApiResponse`
- Include examples in request/response schemas
- Configure Swagger UI for interactive API testing

### Security
- Use Spring Security with OAuth2 Resource Server
- JWT token validation and authorization
- Role-based access control (RBAC)
- Method-level security with `@PreAuthorize`
- CORS configuration for cross-origin requests
- Security headers and CSRF protection

### Database Configuration
- Use Oracle Database (containerized with Podman)
- Spring JDBCTemplate with pure SQL queries (preferred over JPA)
- Use `oracle:thin` JDBC driver
- Configure connection pooling with HikariCP
- Use Flyway for database migrations and versioning
- TestContainers Oracle XE for integration testing

## Application Layer Architecture

Follow this layered architecture pattern:
**API Controllers → Facades → Repositories**

- **Controllers**: Handle HTTP requests/responses, validation, and routing
- **Facades**: Business logic orchestration, transaction management, and service coordination  
- **Repositories**: Data access layer with pure SQL operations

## Example Patterns

### Controller Pattern
```kotlin
@RestController
@RequestMapping("/api/users")
@Tag(name = "User Management", description = "Operations for managing users")
@PreAuthorize("hasRole('USER')")
class UserController(private val userFacade: UserFacade) {
    
    @GetMapping("/{id}")
    @Operation(
        summary = "Get user by ID",
        description = "Retrieves a user by their unique identifier"
    )
    @ApiResponses(value = [
        ApiResponse(responseCode = "200", description = "User found"),
        ApiResponse(responseCode = "404", description = "User not found"),
        ApiResponse(responseCode = "403", description = "Access denied")
    ])
    @PreAuthorize("hasRole('USER') and (#id == authentication.principal.id or hasRole('ADMIN'))")
    fun getUser(
        @Parameter(description = "User ID", example = "123")
        @PathVariable id: Long,
        authentication: Authentication
    ): ResponseEntity<UserDto> =
        userFacade.findById(id)?.let { 
            ResponseEntity.ok(it) 
        } ?: ResponseEntity.notFound().build()
    
    @PostMapping
    @Operation(
        summary = "Create new user",
        description = "Creates a new user with the provided information"
    )
    @ApiResponses(value = [
        ApiResponse(responseCode = "201", description = "User created successfully"),
        ApiResponse(responseCode = "400", description = "Invalid request data"),
        ApiResponse(responseCode = "403", description = "Access denied")
    ])
    @PreAuthorize("hasRole('ADMIN')")
    fun createUser(
        @Valid @RequestBody 
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User creation request",
            required = true
        )
        request: CreateUserRequest,
        authentication: Authentication
    ): ResponseEntity<UserDto> {
        val user = userFacade.createUser(request)
        return ResponseEntity.status(HttpStatus.CREATED).body(user)
    }
}
```

### Facade Pattern (Business Logic Layer)
```kotlin
interface UserFacade {
    fun findById(id: Long): UserDto?
    fun createUser(request: CreateUserRequest): UserDto
    fun updateUserStatus(id: Long, status: String): UserDto?
}

@Service
@Transactional
class UserFacadeImpl(
    private val userRepository: UserRepository,
    private val auditRepository: AuditRepository,
    private val notificationService: NotificationService
) : UserFacade {
    
    override fun findById(id: Long): UserDto? {
        return userRepository.findById(id)?.toDto()
    }
    
    override fun createUser(request: CreateUserRequest): UserDto {
        val user = User(
            email = request.email,
            createdDate = LocalDateTime.now()
        )
        
        val savedUser = userRepository.save(user)
        auditRepository.logUserCreation(savedUser.id)
        notificationService.sendWelcomeEmail(savedUser.email)
        
        return savedUser.toDto()
    }
    
    override fun updateUserStatus(id: Long, status: String): UserDto? {
        val user = userRepository.findById(id) ?: return null
        val updatedUser = userRepository.updateStatus(id, status)
        auditRepository.logStatusChange(id, status)
        return updatedUser?.toDto()
    }
}
```

### Service Pattern (Optional - Use for external integrations)
```kotlin
interface NotificationService {
    fun sendWelcomeEmail(email: String)
}

@Service
class EmailNotificationService : NotificationService {
    override fun sendWelcomeEmail(email: String) {
        // External email service integration
    }
}
```

### Repository Pattern
```kotlin
@Repository
class UserRepository(private val jdbcTemplate: JdbcTemplate) {
    
    fun findById(id: Long): User? {
        return try {
            jdbcTemplate.queryForObject(
                "SELECT user_id, email, created_date FROM users WHERE user_id = ?",
                { rs, _ -> User(
                    id = rs.getLong("user_id"),
                    email = rs.getString("email"),
                    createdDate = rs.getTimestamp("created_date").toLocalDateTime()
                )},
                id
            )
        } catch (e: EmptyResultDataAccessException) {
            null
        }
    }
    
    fun findByEmail(email: String): User? {
        return try {
            jdbcTemplate.queryForObject(
                "SELECT user_id, email, created_date FROM users WHERE email = ?",
                { rs, _ -> User(
                    id = rs.getLong("user_id"),
                    email = rs.getString("email"),
                    createdDate = rs.getTimestamp("created_date").toLocalDateTime()
                )},
                email
            )
        } catch (e: EmptyResultDataAccessException) {
            null
        }
    }
    
    fun findByStatus(status: String): List<User> {
        return jdbcTemplate.query(
            "SELECT user_id, email, created_date FROM users WHERE status = ?",
            { rs, _ -> User(
                id = rs.getLong("user_id"),
                email = rs.getString("email"),
                createdDate = rs.getTimestamp("created_date").toLocalDateTime()
            )},
            status
        )
    }
    
    fun save(user: User): User {
        val id = jdbcTemplate.queryForObject(
            "INSERT INTO users (email, created_date) VALUES (?, ?) RETURNING user_id",
            Long::class.java,
            user.email, 
            Timestamp.valueOf(user.createdDate)
        )
        return user.copy(id = id ?: 0)
    }
    
    fun updateStatus(id: Long, status: String): User? {
        val updated = jdbcTemplate.update(
            "UPDATE users SET status = ? WHERE user_id = ?",
            status, id
        )
        return if (updated > 0) findById(id) else null
    }
}
```

### Entity Pattern (Plain Data Classes)
```kotlin
@Schema(description = "User entity")
data class User(
    @Schema(description = "User unique identifier", example = "123")
    val id: Long = 0,
    
    @Schema(description = "User email address", example = "user@example.com")
    val email: String,
    
    @Schema(description = "User creation timestamp")
    val createdDate: LocalDateTime = LocalDateTime.now()
)
```

### DTO Pattern with OpenAPI Schemas
```kotlin
@Schema(description = "User data transfer object")
data class UserDto(
    @Schema(description = "User unique identifier", example = "123")
    val id: Long,
    
    @Schema(description = "User email address", example = "user@example.com")
    val email: String,
    
    @Schema(description = "User creation date", example = "2025-08-13T10:15:30")
    val createdDate: LocalDateTime
)

@Schema(description = "Request to create a new user")
data class CreateUserRequest(
    @Schema(
        description = "User email address",
        example = "newuser@example.com",
        pattern = "^[A-Za-z0-9+_.-]+@(.+)$"
    )
    @field:Email(message = "Email must be valid")
    @field:NotBlank(message = "Email is required")
    val email: String
)
```

### OpenAPI Configuration
```kotlin
@Configuration
@OpenAPIDefinition(
    info = Info(
        title = "Base Spring Boot API",
        version = "1.0.0",
        description = "Base Spring Boot API template in Kotlin with Oracle DB, OAuth2, and OpenAPI",
        contact = Contact(name = "Development Team", email = "dev@example.com")
    ),
    servers = [
        Server(url = "http://localhost:8080", description = "Local development server"),
        Server(url = "https://api.example.com", description = "Production server")
    ]
)
class OpenApiConfig {
    
    @Bean
    fun customOpenAPI(): OpenAPI {
        return OpenAPI()
            .components(
                Components()
                    .addSecuritySchemes("bearerAuth", 
                        SecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                    )
            )
            .addSecurityItem(SecurityRequirement().addList("bearerAuth"))
    }
}
```

### Security Configuration
```kotlin
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt ->
                    jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
                }
            }
            .authorizeHttpRequests { authz ->
                authz
                    .requestMatchers("/actuator/health").permitAll()
                    .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/public/**").permitAll()
                    .requestMatchers(HttpMethod.POST, "/api/auth/**").permitAll()
                    .anyRequest().authenticated()
            }
            .exceptionHandling { exceptions ->
                exceptions
                    .authenticationEntryPoint(customAuthenticationEntryPoint())
                    .accessDeniedHandler(customAccessDeniedHandler())
            }
            .build()
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        return JwtDecoders.fromIssuerLocation("https://your-oauth2-provider.com")
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val converter = JwtAuthenticationConverter()
        converter.setJwtGrantedAuthoritiesConverter { jwt ->
            val roles = jwt.getClaimAsStringList("roles") ?: emptyList()
            roles.map { SimpleGrantedAuthority("ROLE_$it") }
        }
        return converter
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOriginPatterns = listOf("*")
        configuration.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")
        configuration.allowedHeaders = listOf("*")
        configuration.allowCredentials = true
        
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }

    @Bean
    fun customAuthenticationEntryPoint(): AuthenticationEntryPoint {
        return AuthenticationEntryPoint { _, response, authException ->
            response.contentType = "application/json"
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.writer.write("""{"error": "Unauthorized", "message": "${authException.message}"}""")
        }
    }

    @Bean
    fun customAccessDeniedHandler(): AccessDeniedHandler {
        return AccessDeniedHandler { _, response, accessDeniedException ->
            response.contentType = "application/json"
            response.status = HttpServletResponse.SC_FORBIDDEN
            response.writer.write("""{"error": "Access Denied", "message": "${accessDeniedException.message}"}""")
        }
    }
}
```

### Security Service
```kotlin
@Service
class SecurityService {
    
    fun getCurrentUserId(authentication: Authentication): Long? {
        return when (val principal = authentication.principal) {
            is JwtAuthenticationToken -> principal.token.getClaimAsString("sub")?.toLongOrNull()
            else -> null
        }
    }
    
    fun getCurrentUserRoles(authentication: Authentication): Set<String> {
        return authentication.authorities.map { 
            it.authority.removePrefix("ROLE_") 
        }.toSet()
    }
    
    fun hasRole(authentication: Authentication, role: String): Boolean {
        return authentication.authorities.any { 
            it.authority == "ROLE_$role" 
        }
    }
    
    fun isOwnerOrAdmin(authentication: Authentication, resourceOwnerId: Long): Boolean {
        val currentUserId = getCurrentUserId(authentication)
        return currentUserId == resourceOwnerId || hasRole(authentication, "ADMIN")
    }
}
```