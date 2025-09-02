# Sistema ERP - Enterprise Resource Planning

## Autor
**ThiagoMartins2001**

## Visão Geral
Sistema ERP desenvolvido em Spring Boot com arquitetura MVC, oferecendo funcionalidades de gerenciamento de usuários com autenticação JWT e autorização baseada em roles.

## Tecnologias Utilizadas
- **Java 21**
- **Spring Boot 3.5.5**
- **Spring Security**
- **Spring Data JPA**
- **MySQL 8.0**
- **Docker & Docker Compose**
- **Maven**
- **Lombok**
- **JWT (JSON Web Tokens)**

## Estrutura do Projeto

### Nova Organização Modular
O projeto foi reorganizado para melhor separação de responsabilidades e manutenibilidade:

```
src/main/java/CodingTechnology/ERP/
├── user/                          # Módulo de usuários
│   ├── controller/                # Controladores de usuário
│   │   └── UserController.java
│   ├── model/                     # Entidades de usuário
│   │   └── User.java
│   ├── repository/                # Repositórios de usuário
│   │   └── UserRepository.java
│   └── service/                   # Serviços de usuário
│       └── UserService.java
├── auth/                          # Módulo de autenticação
│   ├── controller/                # Controladores de autenticação
│   │   └── AuthController.java
│   ├── DTO/                       # DTOs de autenticação
│   │   └── AuthRequest.java
│   └── security/                  # Componentes de segurança
│       ├── CustomUserDetailsService.java
│       ├── JwtAuthFilter.java
│       └── JwtService.java
├── config/                        # Configurações da aplicação
│   ├── ApplicationConfig.java
│   └── SecurityConfig.java
└── ErpApplication.java            # Classe principal
```

### Benefícios da Nova Estrutura
- **Modularidade**: Cada funcionalidade tem seu próprio pacote
- **Manutenibilidade**: Código mais organizado e fácil de manter
- **Escalabilidade**: Facilita adição de novos módulos
- **Testabilidade**: Melhor isolamento para testes unitários
- **Reutilização**: Componentes podem ser reutilizados entre módulos
- **Clareza**: Estrutura mais intuitiva para novos desenvolvedores

### Arquitetura MVC
O sistema segue o padrão Model-View-Controller (MVC) com as seguintes camadas:

#### 1. **Model (Modelo)**
Localização: `src/main/java/CodingTechnology/ERP/user/model/`

##### User.java
- **Função**: Entidade JPA que representa um usuário no sistema
- **Campos**:
  - `id`: Identificador único (auto-incremento)
  - `email`: Email do usuário (obrigatório)
  - `username`: Nome de usuário único (obrigatório, único)
  - `password`: Senha criptografada (obrigatório)
  - `role`: Papel/função do usuário (obrigatório)
- **Anotações**: `@Entity`, `@Table`, `@Data` (Lombok)

#### 2. **Repository (Repositório)**
Localização: `src/main/java/CodingTechnology/ERP/user/repository/`

##### UserRepository.java
- **Função**: Interface que estende JpaRepository para operações de banco de dados
- **Métodos**:
  - `findByUsername(String username)`: Busca usuário por username
  - `existsByUsername(String username)`: Verifica se username existe
  - `deleteByUsername(String username)`: Remove usuário por username
  - Métodos herdados: `save()`, `findAll()`, `findById()`, `delete()`

#### 3. **Service (Serviço)**
Localização: `src/main/java/CodingTechnology/ERP/user/service/`

##### UserService.java
- **Função**: Camada de negócio que implementa a lógica de usuários
- **Métodos**:
  - `saveUser(User user)`: Salva usuário com senha criptografada
  - `findByUsername(String username)`: Busca usuário por username
  - `findAllUsers()`: Lista todos os usuários
  - `deleteByUsername(String username)`: Remove usuário por username
- **Funcionalidades**: Criptografia automática de senhas usando BCrypt
- **Transações**: Gerenciamento de transações com `@Transactional`

#### 4. **Controller (Controlador)**
Localização: `src/main/java/CodingTechnology/ERP/user/controller/`

##### UserController.java
- **Função**: Controlador REST que expõe endpoints da API de usuários
- **Endpoints**:
  - `POST /api/users/create`: Cria novo usuário (apenas ADMIN)
  - `GET /api/users/login`: Endpoint de login (simulado)
  - `GET /api/users/listAll`: Lista todos os usuários
  - `DELETE /api/users/delete/{username}`: Remove usuário por username (apenas ADMIN)
- **Respostas**: HTTP Status codes apropriados (201, 200, 409, 403, 404)
- **Autorização**: Sistema de roles com @PreAuthorize

Localização: `src/main/java/CodingTechnology/ERP/auth/controller/`

##### AuthController.java
- **Função**: Controlador REST para autenticação JWT
- **Endpoints**:
  - `POST /api/auth/login`: Autentica usuário e retorna token JWT
- **Funcionalidades**: Autenticação com username/password e geração de token JWT

#### 5. **Security (Segurança)**
Localização: `src/main/java/CodingTechnology/ERP/auth/security/`

##### SecurityConfig.java
- **Função**: Configuração de segurança do Spring Security
- **Funcionalidades**:
  - Desabilita CSRF
  - Configura autenticação JWT
  - Define endpoints públicos e protegidos
  - Configura BCrypt para criptografia de senhas
  - Configura AuthenticationProvider
  - Habilita Method Security com @EnableMethodSecurity
  - Configura sessões stateless para JWT

##### JwtService.java
- **Função**: Serviço para geração e validação de tokens JWT
- **Funcionalidades**:
  - Geração de tokens JWT
  - Validação de tokens
  - Extração de claims
  - Verificação de expiração
  - Configuração de chave secreta e expiração

##### JwtAuthFilter.java
- **Função**: Filtro para autenticação JWT
- **Funcionalidades**:
  - Intercepta requisições com header Authorization
  - Valida tokens JWT
  - Configura autenticação no SecurityContext
  - Suporte a Bearer tokens

##### CustomUserDetailsService.java
- **Função**: Serviço customizado para autenticação de usuários
- **Funcionalidades**:
  - Carrega usuários do banco de dados
  - Converte roles para autoridades do Spring Security
  - Integra com UserRepository

#### 6. **DTO (Data Transfer Object)**
Localização: `src/main/java/CodingTechnology/ERP/auth/DTO/`

##### AuthRequest.java
- **Função**: DTO para requisições de autenticação
- **Campos**:
  - `username`: Nome de usuário
  - `password`: Senha

#### 7. **Configuration (Configuração)**
Localização: `src/main/java/CodingTechnology/ERP/config/`

##### ApplicationConfig.java
- **Função**: Configuração de beans de autenticação
- **Funcionalidades**:
  - Configura UserDetailsService
  - Configura AuthenticationProvider
  - Configura AuthenticationManager
  - Configura PasswordEncoder

#### 8. **Application (Aplicação Principal)**
Localização: `src/main/java/CodingTechnology/ERP/`

##### ErpApplication.java
- **Função**: Classe principal da aplicação Spring Boot
- **Funcionalidades**:
  - Inicializa a aplicação
  - Implementa CommandLineRunner para criação automática do usuário master
  - Cria usuário administrador padrão (master@erp.com / Master@123)

## Configurações

### Banco de Dados
- **Tipo**: MySQL 8.0
- **Porta**: 2311
- **Database**: erp_database
- **Usuário**: admin
- **Senha**: admin
- **Configuração**: `application.properties`

### JWT
- **Chave Secreta**: Configurada em `application.properties`
- **Expiração**: 24 horas (86400000 ms)
- **Algoritmo**: HMAC-SHA256

### Docker
- **Arquivo**: `docker-compose.yml`
- **Serviço**: MySQL 8.0
- **Volumes**: Persistência de dados em `./data`
- **Porta**: 2311:3306

### Aplicação
- **Porta**: 8081
- **URL Base**: http://localhost:8081
- **DDL**: Auto-update (Hibernate)

## Funcionalidades da API

### 1. **Autenticação JWT**
- **Endpoint**: `POST /api/auth/login`
- **Acesso**: Público
- **Corpo da Requisição**:
```json
{
  "username": "master",
  "password": "Master@123"
}
```
- **Resposta**: 
  - 200: Token JWT gerado
  - 400: Credenciais inválidas

### 2. **Criação de Usuário (Admin)**
- **Endpoint**: `POST /api/users/create`
- **Acesso**: Apenas ADMIN
- **Autenticação**: JWT Bearer Token obrigatório
- **Corpo da Requisição**:
```json
{
  "username": "novo_usuario",
  "email": "novo@empresa.com",
  "password": "senha123",
  "role": "USER"
}
```
- **Resposta**: 
  - 201: Usuário criado com sucesso
  - 409: Username já em uso
  - 403: Acesso negado (não é ADMIN)
  - 401: Autenticação necessária

### 3. **Login de Usuário**
- **Endpoint**: `GET /api/users/login`
- **Autenticação**: JWT Bearer Token
- **Resposta**: 200 - Acesso confirmado

### 4. **Listagem de Usuários**
- **Endpoint**: `GET /api/users/listAll`
- **Autenticação**: JWT Bearer Token obrigatório
- **Resposta**: Lista de todos os usuários (200)

### 5. **Exclusão de Usuário (Admin)**
- **Endpoint**: `DELETE /api/users/delete/{username}`
- **Acesso**: Apenas ADMIN
- **Autenticação**: JWT Bearer Token obrigatório
- **Parâmetros**: `username` (path variable)
- **Resposta**: 
  - 200: Usuário removido com sucesso
  - 404: Usuário não encontrado
  - 403: Acesso negado (não é ADMIN)
  - 401: Autenticação necessária

## Sistema de Autorização

### Roles Disponíveis
- **ADMIN**: Acesso total ao sistema
- **USER**: Acesso limitado

### Matriz de Permissões

| Endpoint | ADMIN | USER | Público |
|----------|-------|------|---------|
| POST /api/auth/login | ✅ | ✅ | ✅ |
| POST /api/users/create | ✅ | ❌ | ❌ |
| GET /api/users/login | ✅ | ✅ | ❌ |
| GET /api/users/listAll | ✅ | ✅ | ❌ |
| DELETE /api/users/delete/{username} | ✅ | ❌ | ❌ |

### Anotação @PreAuthorize
O sistema utiliza a anotação `@PreAuthorize("hasRole('ADMIN')")` para controlar o acesso aos endpoints `/create` e `/delete/{username}`, garantindo que apenas administradores possam criar e remover usuários.

## Segurança

### Autenticação
- **Método**: JWT (JSON Web Tokens)
- **Criptografia**: BCrypt para senhas
- **Armazenamento**: Banco de dados MySQL
- **Sessões**: Stateless (sem estado)

### Autorização
- **Sistema**: Role-based (RBAC)
- **Roles Disponíveis**: ADMIN, USER
- **Endpoints Protegidos**: Todos exceto `/api/auth/**` e recursos estáticos
- **Method Security**: Controle granular com @PreAuthorize

### Endpoints Públicos
- `/api/auth/**` - Endpoints de autenticação
- `/` - Página inicial
- `/index.html` - Interface web
- `/css/**` - Arquivos CSS
- `/js/**` - Arquivos JavaScript

## Como Executar

### Pré-requisitos
- Java 21
- Docker e Docker Compose
- Maven

### Passos para Execução

1. **Iniciar o Banco de Dados**:
```bash
docker-compose up -d
```

2. **Executar a Aplicação**:
```bash
mvn spring-boot:run
```

3. **Acessar a Aplicação**:
- Web: http://localhost:8081
- API: http://localhost:8081/api/users

### Usuário Padrão
- **Username**: master
- **Email**: master@erp.com
- **Senha**: Master@123
- **Role**: ADMIN

## Exemplos de Uso

### Autenticação JWT
```bash
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "master",
    "password": "Master@123"
  }'
```

### Criação de Usuário (Admin)
```bash
curl -X POST http://localhost:8081/api/users/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -d '{
    "username": "maria",
    "email": "maria@empresa.com",
    "password": "Senha123",
    "role": "USER"
  }'
```

### Login
```bash
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:8081/api/users/login
```

### Listar Usuários
```bash
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:8081/api/users/listAll
```

### Excluir Usuário (Admin)
```bash
curl -X DELETE \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:8081/api/users/delete/maria
```

## Estrutura de Arquivos

```
ERP/
├── src/main/java/CodingTechnology/ERP/
│   ├── user/
│   │   ├── controller/
│   │   │   └── UserController.java
│   │   ├── model/
│   │   │   └── User.java
│   │   ├── repository/
│   │   │   └── UserRepository.java
│   │   └── service/
│   │       └── UserService.java
│   ├── auth/
│   │   ├── controller/
│   │   │   └── AuthController.java
│   │   ├── DTO/
│   │   │   └── AuthRequest.java
│   │   └── security/
│   │       ├── CustomUserDetailsService.java
│   │       ├── JwtAuthFilter.java
│   │       └── JwtService.java
│   ├── config/
│   │   ├── ApplicationConfig.java
│   │   └── SecurityConfig.java
│   └── ErpApplication.java
├── src/main/resources/
│   ├── application.properties
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── index.html
│   └── templates/
├── data/ (dados do MySQL)
├── docker-compose.yml
├── pom.xml
└── README.md
```

## Dependências Principais

### Spring Boot Starters
- `spring-boot-starter-web`: Web MVC
- `spring-boot-starter-data-jpa`: JPA e Hibernate
- `spring-boot-starter-security`: Segurança
- `spring-boot-devtools`: Desenvolvimento

### Banco de Dados
- `mysql-connector-j`: Driver MySQL

### JWT
- `jjwt-api`: API JWT
- `jjwt-impl`: Implementação JWT
- `jjwt-jackson`: Serialização JWT

### Utilitários
- `lombok`: Redução de boilerplate
- `spring-security-test`: Testes de segurança

## Funcionalidades Implementadas

### Sistema JWT
- **Autenticação**: Endpoint `/api/auth/login` para geração de tokens
- **Validação**: Filtro JWT para validação automática de tokens
- **Sessões**: Sistema stateless com tokens JWT
- **Segurança**: Chave secreta configurável e expiração de tokens

### Endpoint POST /api/users/create
- **Propósito**: Criação de usuários por administradores
- **Segurança**: Restrito apenas para usuários com role ADMIN
- **Uso**: Para administradores criarem novos usuários no sistema

### Endpoint DELETE /api/users/delete/{username}
- **Propósito**: Exclusão de usuários por administradores
- **Segurança**: Restrito apenas para usuários com role ADMIN
- **Parâmetros**: Username do usuário a ser removido
- **Uso**: Para administradores removerem usuários do sistema

### Sistema de Autorização Aprimorado
- **@PreAuthorize**: Anotação para controle granular de acesso
- **Method Security**: Segurança em nível de método
- **Role-based Access**: Controle baseado em roles
- **Transações**: Gerenciamento de transações com @Transactional

### Modelo User Atualizado
- **Campo username**: Adicionado campo único para identificação
- **Validação**: Username único no sistema
- **Compatibilidade**: Mantém campo email para contato

## Funcionalidades Futuras Sugeridas

1. **Gestão de Produtos**
2. **Controle de Estoque**
3. **Gestão de Clientes**
4. **Relatórios e Dashboards**
5. **Sistema de Notificações**
6. **Auditoria de Logs**
7. **API REST mais robusta**
8. **Interface Web moderna**
9. **Refresh Tokens**
10. **Sistema de permissões mais granular**
11. **Endpoint de registro público**
12. **Validação de entrada com Bean Validation**
13. **Rate Limiting**
14. **MFA (Multi-Factor Authentication)**

## Status do Sistema JWT

**⚠️ IMPORTANTE**: O sistema JWT está implementado mas ainda não foi testado completamente. As funcionalidades incluem:

- ✅ Geração de tokens JWT
- ✅ Validação de tokens JWT
- ✅ Filtro de autenticação JWT
- ✅ Configuração de segurança JWT
- ✅ Endpoint de login JWT
- ⚠️ **Pendente**: Testes de integração
- ⚠️ **Pendente**: Validação de cenários de erro
- ⚠️ **Pendente**: Testes de segurança

## Contato
**Autor**: ThiagoMartins2001

---

*Documentação atualizada em: Dezembro 2024*
