# Copilot Instructions: Kotlin Spring Boot API

> **📝 Guidelines for Updates**: Keep these instructions concise and focused. Prioritize essential patterns and actionable guidance over verbose explanations. Aim for practical examples that demonstrate the preferred approach rather than detailed theory. Maximum target: ~150 lines total.

## Stack & Architecture
- **Stack**: Kotlin + Spring Boot 3.x + Maven + Oracle DB + OAuth2/JWT
- **Pattern**: RESTful API with SOLID principles
- **Layers**: Controllers → Facades → Repositories (no JPA, pure SQL)

## Key Standards

### Code Structure
```
src/main/kotlin/
├── controller/     # @RestController - HTTP endpoints
├── facade/         # @Service @Transactional - business logic orchestration  
├── repository/     # @Repository - data access with JDBCTemplate
├── model/          # data classes for entities
├── dto/            # data classes for API contracts
├── config/         # @Configuration classes
└── exception/      # custom exceptions + @ControllerAdvice
```

### Kotlin & Spring Conventions
- **Naming**: PascalCase classes, camelCase functions, UPPER_SNAKE_CASE constants
- **Injection**: Constructor injection, program against interfaces
- **Kotlin**: data classes for DTOs/entities, null safety (`?`, `?.`), prefer `val`
- **Controllers**: `@RestController`, return `ResponseEntity<T>`, use `@Valid`
- **Security**: `@PreAuthorize` method-level, JWT validation, RBAC

### Testing & Documentation
- **Testing**: Kotest + MockK, `@SpringBootTest` for integration, TestContainers
- **API Docs**: OpenAPI 3.0, comprehensive `@Operation/@Schema` annotations
- **DB**: Oracle with Flyway migrations, HikariCP connection pooling

## Essential Patterns

### Controller Example
```kotlin
@RestController
@RequestMapping("/api/users")
@Tag(name = "User Management")
@PreAuthorize("hasRole('USER')")
class UserController(private val userFacade: UserFacade) {
    
    @GetMapping("/{id}")
    @Operation(summary = "Get user by ID")
    @PreAuthorize("hasRole('USER') and (#id == authentication.principal.id or hasRole('ADMIN'))")
    fun getUser(@PathVariable id: Long): ResponseEntity<UserDto> =
        userFacade.findById(id)?.let { ResponseEntity.ok(it) } 
            ?: ResponseEntity.notFound().build()
    
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    fun createUser(@Valid @RequestBody request: CreateUserRequest): ResponseEntity<UserDto> {
        val user = userFacade.createUser(request)
        return ResponseEntity.status(HttpStatus.CREATED).body(user)
    }
}
```

### Facade Example
```kotlin
@Service
@Transactional
class UserFacadeImpl(
    private val userRepository: UserRepository,
    private val auditRepository: AuditRepository
) : UserFacade {
    
    override fun createUser(request: CreateUserRequest): UserDto {
        val user = userRepository.save(User(email = request.email))
        auditRepository.logUserCreation(user.id)
        return user.toDto()
    }
}
```

### Repository Example
```kotlin
@Repository
class UserRepository(private val jdbcTemplate: JdbcTemplate) {
    
    fun findById(id: Long): User? = try {
        jdbcTemplate.queryForObject(
            "SELECT user_id, email FROM users WHERE user_id = ?",
            { rs, _ -> User(rs.getLong("user_id"), rs.getString("email")) },
            id
        )
    } catch (e: EmptyResultDataAccessException) { null }
    
    fun save(user: User): User {
        val id = jdbcTemplate.queryForObject(
            "INSERT INTO users (email) VALUES (?) RETURNING user_id",
            Long::class.java, user.email
        )
        return user.copy(id = id ?: 0)
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
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http.csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .oauth2ResourceServer { it.jwt { } }
            .authorizeHttpRequests { authz ->
                authz.requestMatchers("/actuator/health", "/swagger-ui/**").permitAll()
                    .anyRequest().authenticated()
            }.build()
}