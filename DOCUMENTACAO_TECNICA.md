# Documentação Técnica - Sistema ERP

## Autor
**ThiagoMartins2001**

## Especificações Técnicas

### Versões das Tecnologias
- **Java**: 21 (LTS)
- **Spring Boot**: 3.5.5
- **Spring Security**: 6.x
- **Spring Data JPA**: 3.x
- **Hibernate**: 6.x
- **MySQL**: 8.0
- **Maven**: 3.x

### Arquitetura do Sistema

#### Padrão MVC Implementado
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Controller    │    │     Service     │    │   Repository    │
│   (REST API)    │◄──►│  (Business      │◄──►│   (Data Access) │
│                 │    │   Logic)        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Model/Entity  │    │   Security      │    │   Database      │
│   (User.java)   │    │   (Auth/Author) │    │   (MySQL)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Análise Detalhada das Classes

### 1. **User.java** - Entidade Principal
```java
@Entity
@Table(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "email", nullable = false, unique = true)
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private String role;
}
```

**Características Técnicas:**
- **Mapeamento JPA**: Tabela `users` no banco de dados
- **Chave Primária**: Auto-incremento (IDENTITY)
- **Constraints**: Email único e obrigatório
- **Lombok**: Anotação `@Data` gera getters, setters, equals, hashCode e toString

### 2. **UserRepository.java** - Camada de Acesso a Dados
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
    boolean existsByEmail(String email);
}
```

**Métodos Disponíveis:**
- **Herdados do JpaRepository**:
  - `save(User entity)`: Salva ou atualiza entidade
  - `findById(Long id)`: Busca por ID
  - `findAll()`: Lista todas as entidades
  - `delete(User entity)`: Remove entidade
  - `count()`: Conta total de entidades
- **Customizados**:
  - `findByEmail(String email)`: Busca por email
  - `existsByEmail(String email)`: Verifica existência por email

### 3. **UserService.java** - Lógica de Negócio
```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
    
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
    
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }
}
```

**Funcionalidades de Segurança:**
- **Criptografia Automática**: BCrypt para todas as senhas
- **Injeção de Dependência**: UserRepository e PasswordEncoder
- **Transações**: Gerenciadas automaticamente pelo Spring

### 4. **UserController.java** - API REST
```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;
    
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        // Lógica de registro
    }
    
    @GetMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody User user) {
        // Endpoint de login
    }
    
    @GetMapping("/listAll")
    public ResponseEntity<List<User>> listAllUsers() {
        // Listagem de usuários
    }
}
```

**Endpoints da API:**

#### POST /api/users/register
- **Função**: Registra novo usuário
- **Content-Type**: application/json
- **Corpo**:
```json
{
  "email": "usuario@exemplo.com",
  "password": "senha123",
  "role": "USER"
}
```
- **Respostas**:
  - `201 Created`: Usuário registrado com sucesso
  - `409 Conflict`: Email já existe
  - `400 Bad Request`: Dados inválidos

#### GET /api/users/login
- **Função**: Endpoint de autenticação
- **Autenticação**: HTTP Basic
- **Resposta**: `200 OK` - Acesso confirmado

#### GET /api/users/listAll
- **Função**: Lista todos os usuários
- **Autenticação**: Obrigatória
- **Resposta**: `200 OK` - Lista de usuários em JSON

### 5. **SecurityConfig.java** - Configuração de Segurança
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeHttpRequests()
            .requestMatchers("/", "/index.html", "/css/**", "/js/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .httpBasic();
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

**Configurações de Segurança:**
- **CSRF**: Desabilitado para API REST
- **Autenticação**: HTTP Basic
- **Endpoints Públicos**: Recursos estáticos
- **Criptografia**: BCrypt com força padrão (10 rounds)

### 6. **CustomUserDetailsService.java** - Autenticação Customizada
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("Usuário não encontrado: " + email);
        }
        
        List<GrantedAuthority> authorities = Collections.singletonList(
            new SimpleGrantedAuthority("ROLE_" + user.getRole())
        );
        
        return new org.springframework.security.core.userdetails.User(
            user.getEmail(), 
            user.getPassword(), 
            authorities
        );
    }
}
```

**Funcionalidades:**
- **Carregamento de Usuários**: Do banco de dados
- **Autoridades**: Conversão de roles para Spring Security
- **Tratamento de Erros**: UsernameNotFoundException

## Integração com Banco de Dados

### Configuração MySQL
```properties
spring.datasource.url=jdbc:mysql://localhost:2311/erp_database
spring.datasource.username=admin
spring.datasource.password=admin
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
server.port=8081
```

**Parâmetros de Conexão:**
- **Host**: localhost
- **Porta**: 2311
- **Database**: erp_database
- **Usuário**: admin
- **Senha**: admin
- **DDL**: Auto-update (cria/atualiza tabelas automaticamente)
- **SQL Logging**: Habilitado para desenvolvimento

### Docker Compose
```yaml
version: '3.8'
services:
  db:
    image: mysql:8.0
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: Mudar123
      MYSQL_DATABASE: erp_database
      MYSQL_USER: admin
      MYSQL_PASSWORD: admin
    ports:
      - "2311:3306"
    volumes:
      - ./data:/var/lib/mysql
```

**Configurações do Container:**
- **Imagem**: MySQL 8.0 oficial
- **Restart**: Sempre
- **Porta**: 2311 externa → 3306 interna
- **Volumes**: Persistência em `./data`

## Estrutura de Dados

### Tabela `users`
```sql
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL
);
```

**Índices:**
- **PRIMARY KEY**: `id`
- **UNIQUE**: `email`

### Dados Iniciais
```sql
INSERT INTO users (email, password, role) VALUES 
('master@erp.com', '$2a$10$...', 'ADMIN');
```

## Fluxo de Autenticação

```
1. Cliente faz requisição com credenciais
   ↓
2. Spring Security intercepta
   ↓
3. CustomUserDetailsService carrega usuário
   ↓
4. BCrypt verifica senha
   ↓
5. Authorities são criadas baseadas no role
   ↓
6. Acesso é concedido/negado
```

## Logs e Monitoramento

### Logs de Desenvolvimento
- **SQL**: Habilitado (`spring.jpa.show-sql=true`)
- **Hibernate**: DDL automático
- **Spring Boot**: Logs padrão

### Pontos de Monitoramento
- **Registro de Usuários**: Logs de criação
- **Autenticação**: Sucessos e falhas
- **Banco de Dados**: Queries executadas

## Testes

### Endpoints para Teste
```bash
# Registro de usuário
curl -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"email":"teste@exemplo.com","password":"123456","role":"USER"}'

# Login (HTTP Basic)
curl -u teste@exemplo.com:123456 \
  http://localhost:8081/api/users/login

# Listar usuários (autenticado)
curl -u master@erp.com:Master@123 \
  http://localhost:8081/api/users/listAll
```

## Considerações de Segurança

### Implementadas
- ✅ Criptografia BCrypt para senhas
- ✅ Autenticação HTTP Basic
- ✅ Autorização baseada em roles
- ✅ Validação de email único
- ✅ Endpoints protegidos

### Recomendações Futuras
- 🔒 Implementar JWT tokens
- 🔒 Rate limiting
- 🔒 Validação de entrada
- 🔒 Logs de auditoria
- 🔒 HTTPS em produção

## Performance

### Otimizações Atuais
- **Connection Pool**: HikariCP (padrão Spring Boot)
- **Lazy Loading**: JPA/Hibernate
- **Índices**: Email único

### Monitoramento
- **Queries**: Logs habilitados
- **Tempo de Resposta**: Logs do Spring Boot
- **Memória**: JVM padrão

## Deploy e Produção

### Configurações de Produção
```properties
# application-prod.properties
spring.jpa.show-sql=false
spring.jpa.hibernate.ddl-auto=validate
logging.level.root=WARN
server.port=8080
```

### Variáveis de Ambiente
```bash
export SPRING_PROFILES_ACTIVE=prod
export DB_HOST=production-db-host
export DB_PASSWORD=secure-password
```

---

**Autor**: ThiagoMartins2001  
**Versão**: 1.0  
**Data**: $(date)
