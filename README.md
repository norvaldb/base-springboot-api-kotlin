# Base Spring Boot API - Kotlin

A comprehensive Spring Boot API template built with Kotlin, following SOLID principles and best practices.

## 🚀 Features

- **Kotlin** - Modern, concise language with null safety
- **Spring Boot 3.x** - Latest Spring Boot with native compilation support
- **Oracle Database** - Enterprise-grade database with containerized development
- **OAuth2 Resource Server** - JWT-based authentication and authorization
- **OpenAPI/Swagger** - Interactive API documentation
- **JDBCTemplate** - Direct SQL access with manual mapping
- **Flyway** - Database migrations and versioning
- **Kotest** - Kotlin-native testing framework
- **TestContainers** - Integration testing with real database
- **JaCoCo** - Code coverage analysis and reporting
- **Allure** - Advanced test reporting with coverage integration
- **Maven** - Dependency management and build automation
- **SOLID Principles** - Clean architecture implementation

## 🏗️ Architecture

### Layered Architecture Pattern
```
API Controllers → Facades → Repositories
```

- **Controllers**: Handle HTTP requests/responses, validation, and routing
- **Facades**: Business logic orchestration, transaction management, and service coordination  
- **Repositories**: Data access layer with pure SQL operations

### Project Structure
```
src/main/kotlin/
├── controller/     # REST endpoints (@RestController)
├── facade/         # Business logic layer (@Service, @Transactional)
├── service/        # External service integrations
├── repository/     # Data access layer (@Repository)
├── model/          # Entity classes (plain data classes)
├── dto/            # Data Transfer Objects with OpenAPI schemas
├── config/         # Configuration classes (@Configuration)
└── exception/      # Custom exceptions and handlers
```

## 🛠️ Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Kotlin | 1.9.24 |
| Framework | Spring Boot | 3.3.2 |
| Build Tool | Maven | 3.9.x |
| Database | Oracle Database | 23ai |
| Connection Pool | HikariCP | Built-in |
| Migration | Flyway | 10.15.2 |
| Documentation | SpringDoc OpenAPI | 2.6.0 |
| Security | Spring Security OAuth2 | Built-in |
| Testing | Kotest + MockK | 5.9.1 |
| Containers | TestContainers | 1.19.8 |

## 🚦 Getting Started

### Prerequisites

- **Java 21+**
- **Maven 3.6+**
- **Docker/Podman** (for Oracle Database)
- **Git**

### 1. Clone the Repository

```bash
git clone https://github.com/norvaldb/base-springboot-api-kotlin.git
cd base-springboot-api-kotlin
```

### 2. Start Oracle Database (Podman)

```bash
# Pull Oracle XE image
podman pull container-registry.oracle.com/database/express:latest

# Run Oracle XE container
podman run -d \
  --name oracle-xe \
  -p 1521:1521 \
  -e ORACLE_PWD=password123 \
  -e ORACLE_CHARACTERSET=AL32UTF8 \
  container-registry.oracle.com/database/express:latest

# Wait for database to be ready (2-3 minutes)
podman logs -f oracle-xe
```

### 3. Configure Environment Variables

```bash
export DB_USERNAME=dev_user
export DB_PASSWORD=dev_password
export DB_SCHEMA=DEV_SCHEMA
export JWT_ISSUER_URI=https://your-oauth2-provider.com
```

### 4. Run Database Migrations

```bash
# Create database schema and user (connect as system)
sqlplus system/password123@localhost:1521/XEPDB1

# In SQL*Plus:
CREATE USER dev_user IDENTIFIED BY dev_password;
GRANT DBA TO dev_user;
CREATE SCHEMA AUTHORIZATION dev_user;

# Run Flyway migrations
mvn flyway:migrate
```

### 5. Build and Run

```bash
# Build the application with automatic reports
mvn clean install

# Run tests only
mvn test

# Run integration tests
mvn verify

# Generate code coverage report (manual)
mvn jacoco:report

# Generate Allure report (manual)
mvn allure:report

# Start the application
mvn spring-boot:run
```

## 📊 Code Coverage & Reporting

### Automatic Report Generation
Both JaCoCo coverage and Allure test reports are **automatically generated** during `mvn install`:

```bash
# Single command generates everything
mvn clean install
```

**Generated Reports:**
- **JaCoCo Coverage**: `target/site/jacoco/index.html`
- **Allure Test Report**: `target/allure-report/index.html`

### Manual Report Generation
### Manual Report Generation
For individual report generation (optional):

```bash
# Generate coverage report only
mvn jacoco:report

# Generate Allure report only
mvn allure:report

# Serve interactive Allure report
mvn allure:serve
```

### Allure Test Reports
### Allure Test Reports
```bash
# Serve interactive Allure report
mvn allure:serve
```

**Coverage Reports Location:**
- **JaCoCo HTML**: `target/site/jacoco/index.html`
- **JaCoCo XML**: `target/site/jacoco/jacoco.xml` (for CI/CD)
- **Allure Report**: `target/allure-report/index.html`

**Performance Optimizations:**
- Kotest autoscan disabled for faster test startup
- Reports generated automatically during build lifecycle

**Coverage Thresholds:**
- Coverage enforcement is available but currently disabled
- Uncomment the `jacoco-check` execution in `pom.xml` to enable
- Default thresholds: Instruction 70%, Branch 60%

### 6. Access the Application

- **API Base URL**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **API Docs**: http://localhost:8080/v3/api-docs
- **Health Check**: http://localhost:8080/actuator/health

## 📖 API Documentation

The API is fully documented using OpenAPI 3.0 specification. Visit the Swagger UI at http://localhost:8080/swagger-ui.html for interactive documentation.

### Authentication

The API uses OAuth2 JWT Bearer tokens for authentication:

```http
Authorization: Bearer <your-jwt-token>
```

### Example Endpoints

- `GET /api/users/{id}` - Get user by ID
- `POST /api/users` - Create new user
- `GET /actuator/health` - Health check

## 🧪 Testing

### Unit Tests with Kotest

```bash
# Run unit tests
mvn test
```

### Integration Tests with TestContainers

```bash
# Run integration tests (includes TestContainers)
mvn verify
```

### Allure Report

This project is configured to produce Allure results for both unit and integration tests.

- Results directory: `target/allure-results`
- Generate static report: `mvn allure:report` (output in `target/site/allure-maven/index.html`)
- Serve report locally: `mvn allure:serve`

Notes:
- Kotest integrates with Allure via `AllureTestReporter`. See `src/test/kotlin/ProjectConfig.kt`.
- The Allure Maven plugin is not bound to the lifecycle; run the goals above after `mvn test` or `mvn verify`.

### Example Test Structure

```kotlin
class UserFacadeTest : FunSpec({
    
    val userRepository = mockk<UserRepository>()
    val userFacade = UserFacadeImpl(userRepository)
    
    test("should find user by id") {
        // Given
        val userId = 1L
        val user = User(id = userId, email = "test@example.com")
        every { userRepository.findById(userId) } returns user
        
        // When
        val result = userFacade.findById(userId)
        
        // Then
        result shouldNotBe null
        result?.id shouldBe userId
        result?.email shouldBe "test@example.com"
    }
})
```

## 🗄️ Database

### Oracle Database Setup

The application uses Oracle Database 23ai with the following configuration:

- **Connection**: `jdbc:oracle:thin:@localhost:1521:XEPDB1`
- **Schema**: Configurable via `DB_SCHEMA` environment variable
- **Connection Pool**: HikariCP with optimized settings

### Flyway Migrations

Database migrations are located in `src/main/resources/db/migration/`:

```
db/migration/
├── V1__Create_users_table.sql
├── V2__Add_user_indexes.sql
└── V3__Create_audit_tables.sql
```

### Example Migration

```sql
-- V1__Create_users_table.sql
CREATE TABLE users (
    user_id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    email VARCHAR2(255) NOT NULL UNIQUE,
    status VARCHAR2(50) DEFAULT 'ACTIVE',
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
```

## 🔧 Configuration

### Application Profiles

- **dev** - Development profile with debug logging
- **test** - Testing profile with TestContainers
- **prod** - Production profile with optimized settings

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_USERNAME` | Database username | dev_user |
| `DB_PASSWORD` | Database password | dev_password |
| `DB_SCHEMA` | Database schema | DEV_SCHEMA |
| `JWT_ISSUER_URI` | OAuth2 JWT issuer | https://your-oauth2-provider.com |
| `CORS_ALLOWED_ORIGINS` | CORS allowed origins | http://localhost:3000 |

## 📋 Development Guidelines

This project follows the comprehensive Copilot instructions located in `.github/copilot-instructions.md`. Key principles:

### SOLID Principles
- **Single Responsibility**: Each class has one clear purpose
- **Open/Closed**: Extensible through interfaces
- **Liskov Substitution**: Proper inheritance hierarchies
- **Interface Segregation**: Focused, specific interfaces
- **Dependency Inversion**: Depend on abstractions

### Code Standards
- Use data classes for DTOs and entities
- Prefer `val` over `var`
- Leverage Kotlin null safety
- Use constructor injection
- Follow REST conventions
- Comprehensive error handling

### Security
- OAuth2 JWT validation
- Role-based access control
- Method-level security
- CORS configuration
- Security headers

## 🐳 Docker Support

### Development with Podman

```bash
# Start Oracle Database
podman run -d \
  --name oracle-xe \
  -p 1521:1521 \
  -e ORACLE_PWD=password123 \
  container-registry.oracle.com/database/express:latest
```

### Application Container (Future)

```dockerfile
FROM openjdk:21-jdk-slim
COPY target/base-springboot-api-kotlin-*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow the coding standards in `.github/copilot-instructions.md`
4. Add tests for new functionality
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For questions and support:

- Create an [Issue](https://github.com/norvaldb/base-springboot-api-kotlin/issues)
- Check the [Copilot Instructions](.github/copilot-instructions.md)
- Review the [API Documentation](http://localhost:8080/swagger-ui.html)

---

**Built with ❤️ using Kotlin and Spring Boot**