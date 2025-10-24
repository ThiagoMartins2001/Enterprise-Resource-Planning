# Sistema ERP - Enterprise Resource Planning

## Autor
**ThiagoMartins2001**

## Visão Geral
Sistema ERP desenvolvido em Spring Boot com arquitetura MVC, oferecendo funcionalidades de gerenciamento de usuários com autenticação JWT e autorização baseada em roles. O sistema implementa um controle de acesso robusto com diferentes níveis de permissão.

## Tecnologias Utilizadas
- **Java 21**
- **Spring Boot 3.3.0**
- **Spring Security**
- **Spring Data JPA**
- **MySQL 8.0**
- **Docker & Docker Compose**
- **Maven**
- **Lombok**
- **JWT (JSON Web Tokens)**
- **BCrypt** (Criptografia de senhas)

## Estrutura do Projeto

### Organização Modular
O projeto foi organizado seguindo princípios de separação de responsabilidades:

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
│       ├── JwtAuthFilter.java
│       └── JwtService.java
├── config/                        # Configurações da aplicação
│   └── SecurityConfiguration.java
└── ErpApplication.java            # Classe principal
```

## Funcionalidades Atuais

### 1. **Sistema de Autenticação JWT**
- Autenticação segura com tokens JWT
- Expiração de tokens configurável
- Filtro de autenticação automático
- Criptografia de senhas com BCrypt

### 2. **Gerenciamento de Usuários**
- Criação de usuários (apenas administradores)
- Listagem de todos os usuários
- Exclusão de usuários (apenas administradores)
- Sistema de roles (ADMIN, RH, USER)

### 3. **Controle de Acesso**
- Autorização baseada em roles
- Endpoints protegidos por JWT
- Diferentes níveis de permissão

## Configuração e Instalação

### Pré-requisitos
- Java 21
- Maven 3.6+
- Docker e Docker Compose
- MySQL 8.0 (via Docker)

### 1. Clone o Repositório
```bash
git clone <url-do-repositorio>
cd ERP
```

### 2. Configuração do Banco de Dados com Docker

#### Iniciando o Container MySQL
```bash
# Na raiz do projeto, execute:
docker-compose up -d
```

Isso irá:
- Criar um container MySQL 8.0
- Configurar o banco `erp_database`
- Mapear a porta 2311 para 3306
- Persistir dados na pasta `./data`

#### Verificando se o Container está Rodando
```bash
docker ps
```

### 3. Executando a Aplicação

#### Via Maven
```bash
mvn spring-boot:run
```

#### Via JAR
```bash
mvn clean package
java -jar target/ERP-0.0.1-SNAPSHOT.jar
```

A aplicação estará disponível em: `http://localhost:8081`

## Configuração do Usuário Administrador

⚠️ **IMPORTANTE**: Na primeira execução, o sistema cria automaticamente um usuário administrador:

- **Username**: `UserAdmin`
- **Password**: `Master@123`
- **Role**: `ADMIN`

### Alterando as Credenciais do Administrador
Para alterar as credenciais antes da primeira execução, edite o arquivo:
`src/main/java/CodingTechnology/ERP/ErpApplication.java`

```java
// Linhas 30-32
masterUser.setUsername("SeuUsuarioAdmin");
masterUser.setPassword(passwordEncoder.encode("SuaSenhaSegura"));
masterUser.setRole("ADMIN");
```

## API Endpoints

### Base URL
```
http://localhost:8081
```

### 1. **Autenticação JWT**

#### POST /api/auth/login
Autentica um usuário e retorna um token JWT.

**Headers:**
```
Content-Type: application/json
```

**Corpo da Requisição:**
```json
{
    "username": "UserAdmin",
    "password": "Master@123"
}
```

**Resposta de Sucesso (200):**
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Resposta de Erro (400):**
```json
{
    "error": "Invalid credentials"
}
```

### 2. **Criação de Usuário (Apenas ADMIN)**

#### POST /api/users/create
Cria um novo usuário no sistema.

**Headers:**
```
Content-Type: application/json
Authorization: Bearer <seu-token-jwt>
```

**Corpo da Requisição:**
```json
{
    "username": "Usuarioteste",
    "password": "senhaDoRh1234",
    "role": "RH"
}
```

**Resposta de Sucesso (201):**
```
User created successfully:
```

**Resposta de Erro (409):**
```
Name already in use:
```

**Resposta de Erro (403):**
```
Access Denied
```

### 3. **Listagem de Usuários**

#### GET /api/users/listAll
Lista todos os usuários cadastrados.

**Headers:**
```
Authorization: Bearer <seu-token-jwt>
```

**Resposta de Sucesso (200):**
```json
[
    {
        "id": 1,
        "username": "UserAdmin",
        "role": "ADMIN"
    },
    {
        "id": 2,
        "username": "Usuarioteste",
        "role": "RH"
    }
]
```

### 4. **Exclusão de Usuário (Apenas ADMIN)**

#### DELETE /api/users/delete/{username}
Remove um usuário do sistema.

**Headers:**
```
Authorization: Bearer <seu-token-jwt>
```

**Parâmetros:**
- `username`: Nome do usuário a ser excluído

**Resposta de Sucesso (200):**
```
User deleted successfully!
```

**Resposta de Erro (404):**
```
User not found
```

## Testando a API com Postman

### 1. **Configuração Inicial**

1. Abra o Postman
2. Crie uma nova Collection chamada "ERP System"
3. Configure a Base URL: `http://localhost:8081`

### 2. **Teste de Login**

1. **Criar Nova Requisição:**
   - Método: `POST`
   - URL: `http://localhost:8081/api/auth/login`
   - Headers: `Content-Type: application/json`

2. **Body (raw JSON):**
```json
{
    "username": "UserAdmin",
    "password": "Master@123"
}
```

3. **Executar e Copiar o Token:**
   - Após executar, copie o valor do campo `token` da resposta

### 3. **Configurando Autenticação para Outras Requisições**

Para **TODAS** as outras requisições (exceto login):

1. **Vá para a aba "Authorization"**
2. **Selecione "Type": `Bearer Token`**
3. **Cole o token JWT no campo "Token"**
4. **Salve a requisição**

### 4. **Teste de Criação de Usuário**

1. **Criar Nova Requisição:**
   - Método: `POST`
   - URL: `http://localhost:8081/api/users/create`
   - Authorization: Bearer Token (com o token do login)

2. **Body (raw JSON):**
```json
{
    "username": "Usuarioteste",
    "password": "senhaDoRh1234",
    "role": "RH"
}
```

### 5. **Teste de Listagem de Usuários**

1. **Criar Nova Requisição:**
   - Método: `GET`
   - URL: `http://localhost:8081/api/users/listAll`
   - Authorization: Bearer Token (com o token do login)

### 6. **Teste de Exclusão de Usuário**

1. **Criar Nova Requisição:**
   - Método: `DELETE`
   - URL: `http://localhost:8081/api/users/delete/Usuarioteste`
   - Authorization: Bearer Token (com o token do login)

## Sistema de Roles

### Roles Disponíveis
- **ADMIN**: Acesso total ao sistema
  - Pode criar usuários
  - Pode excluir usuários
  - Pode listar usuários
- **RH**: Acesso limitado (futuras implementações)
- **USER**: Acesso básico (futuras implementações)

### Fluxo de Autenticação
1. **Login**: Usuário faz login com username/password
2. **Token**: Sistema retorna token JWT válido por 24 horas
3. **Autorização**: Token é enviado no header `Authorization: Bearer <token>`
4. **Validação**: Sistema valida token e verifica permissões

## Configurações do Sistema

### Banco de Dados
- **Host**: localhost:2311
- **Database**: erp_database
- **Username**: admin
- **Password**: admin
- **Root Password**: Mudar123

### Aplicação
- **Porta**: 8081
- **JWT Secret**: Configurado em `application.properties`
- **JWT Expiration**: 24 horas (86400000 ms)

### Docker
- **MySQL Port**: 2311:3306
- **Data Persistence**: `./data` directory
- **Auto-restart**: Always

## Comandos Úteis

### Docker
```bash
# Iniciar containers
docker-compose up -d

# Parar containers
docker-compose down

# Ver logs
docker-compose logs -f

# Reiniciar apenas o banco
docker-compose restart db
```

### Maven
```bash
# Compilar projeto
mvn clean compile

# Executar testes
mvn test

# Gerar JAR
mvn clean package

# Executar aplicação
mvn spring-boot:run
```

## Troubleshooting

### Problemas Comuns

1. **Erro de Conexão com Banco:**
   - Verifique se o Docker está rodando
   - Confirme se a porta 2311 está livre
   - Execute: `docker-compose logs db`

2. **Token Inválido:**
   - Faça novo login para obter token atualizado
   - Verifique se o token está sendo enviado corretamente

3. **Acesso Negado (403):**
   - Confirme se o usuário tem role ADMIN
   - Verifique se o token é válido

4. **Porta 8081 em Uso:**
   - Altere a porta em `application.properties`
   - Ou pare o processo que está usando a porta

## Próximas Implementações

### v2.1 (Planejado)
- [ ] Gestão de produtos
- [ ] Controle de estoque
- [ ] Sistema de vendas
- [ ] Relatórios básicos
- [ ] Atualização de usuários
- [ ] Logs de auditoria

### v2.2 (Futuro)
- [ ] Dashboard administrativo
- [ ] Sistema de notificações
- [ ] API de relatórios avançados
- [ ] Integração com sistemas externos

## Contribuição

Para contribuir com o projeto:
1. Fork o repositório
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

---

**Desenvolvido por ThiagoMartins2001** 🚀