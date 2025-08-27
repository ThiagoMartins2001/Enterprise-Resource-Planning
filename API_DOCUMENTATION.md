# Documentação da API - Sistema ERP

## Autor
**ThiagoMartins2001**

## Informações Gerais

- **Base URL**: `http://localhost:8081`
- **Content-Type**: `application/json`
- **Autenticação**: HTTP Basic Authentication
- **Versão**: 1.0

## Endpoints Disponíveis

### 1. Registro de Usuário

#### POST /api/users/register
Registra um novo usuário no sistema.

**URL**: `http://localhost:8081/api/users/register`

**Método**: `POST`

**Headers**:
```
Content-Type: application/json
```

**Corpo da Requisição**:
```json
{
  "email": "usuario@exemplo.com",
  "password": "senha123",
  "role": "USER"
}
```

**Parâmetros**:
- `email` (string, obrigatório): Email único do usuário
- `password` (string, obrigatório): Senha do usuário (será criptografada)
- `role` (string, obrigatório): Papel do usuário (ADMIN ou USER)

**Respostas**:

**Sucesso (201 Created)**:
```json
"User registered successfully!"
```

**Erro - Email já existe (409 Conflict)**:
```json
"Email already in use!"
```

**Erro - Dados inválidos (400 Bad Request)**:
```json
{
  "timestamp": "2024-01-01T12:00:00.000+00:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed"
}
```

**Exemplo de Uso (cURL)**:
```bash
curl -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "joao@empresa.com",
    "password": "MinhaSenha123",
    "role": "USER"
  }'
```

**Exemplo de Uso (JavaScript)**:
```javascript
fetch('http://localhost:8081/api/users/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'joao@empresa.com',
    password: 'MinhaSenha123',
    role: 'USER'
  })
})
.then(response => response.text())
.then(data => console.log(data))
.catch(error => console.error('Erro:', error));
```

---

### 2. Criação de Usuário (Admin)

#### POST /api/users/create
Cria um novo usuário no sistema (apenas para administradores).

**URL**: `http://localhost:8081/api/users/create`

**Método**: `POST`

**Autenticação**: Obrigatória (apenas ADMIN)

**Headers**:
```
Content-Type: application/json
Authorization: Basic <base64(email:password)>
```

**Corpo da Requisição**:
```json
{
  "email": "novo@empresa.com",
  "password": "senha123",
  "role": "USER"
}
```

**Parâmetros**:
- `email` (string, obrigatório): Email único do usuário
- `password` (string, obrigatório): Senha do usuário (será criptografada)
- `role` (string, obrigatório): Papel do usuário (ADMIN ou USER)

**Respostas**:

**Sucesso (201 Created)**:
```json
"User created successfully:"
```

**Erro - Email já existe (409 Conflict)**:
```json
"Email already in use:"
```

**Erro - Acesso negado (403 Forbidden)**:
```json
{
  "timestamp": "2024-01-01T12:00:00.000+00:00",
  "status": 403,
  "error": "Forbidden",
  "message": "Access Denied"
}
```

**Exemplo de Uso (cURL)**:
```bash
curl -X POST http://localhost:8081/api/users/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic bWFzdGVyQGVycC5jb206TWFzdGVyQDEyMw==" \
  -d '{
    "email": "maria@empresa.com",
    "password": "Senha123",
    "role": "USER"
  }'
```

**Exemplo de Uso (JavaScript)**:
```javascript
const credentials = btoa('master@erp.com:Master@123');

fetch('http://localhost:8081/api/users/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Basic ${credentials}`
  },
  body: JSON.stringify({
    email: 'maria@empresa.com',
    password: 'Senha123',
    role: 'USER'
  })
})
.then(response => response.text())
.then(data => console.log(data))
.catch(error => console.error('Erro:', error));
```

---

### 3. Login de Usuário

#### GET /api/users/login
Endpoint para autenticação de usuário.

**URL**: `http://localhost:8081/api/users/login`

**Método**: `GET`

**Autenticação**: HTTP Basic

**Headers**:
```
Authorization: Basic <base64(email:password)>
```

**Respostas**:

**Sucesso (200 OK)**:
```json
"You have successfully accessed a secure endpoint!"
```

**Erro - Não autorizado (401 Unauthorized)**:
```json
{
  "timestamp": "2024-01-01T12:00:00.000+00:00",
  "status": 401,
  "error": "Unauthorized",
  "message": "Full authentication is required to access this resource"
}
```

**Exemplo de Uso (cURL)**:
```bash
curl -u joao@empresa.com:MinhaSenha123 \
  http://localhost:8081/api/users/login
```

**Exemplo de Uso (JavaScript)**:
```javascript
const credentials = btoa('joao@empresa.com:MinhaSenha123');

fetch('http://localhost:8081/api/users/login', {
  method: 'GET',
  headers: {
    'Authorization': `Basic ${credentials}`
  }
})
.then(response => response.text())
.then(data => console.log(data))
.catch(error => console.error('Erro:', error));
```

---

### 4. Listagem de Usuários

#### GET /api/users/listAll
Lista todos os usuários registrados no sistema.

**URL**: `http://localhost:8081/api/users/listAll`

**Método**: `GET`

**Autenticação**: Obrigatória (HTTP Basic)

**Headers**:
```
Authorization: Basic <base64(email:password)>
```

**Respostas**:

**Sucesso (200 OK)**:
```json
[
  {
    "id": 1,
    "email": "master@erp.com",
    "password": "$2a$10$...",
    "role": "ADMIN"
  },
  {
    "id": 2,
    "email": "joao@empresa.com",
    "password": "$2a$10$...",
    "role": "USER"
  }
]
```

**Erro - Não autorizado (401 Unauthorized)**:
```json
{
  "timestamp": "2024-01-01T12:00:00.000+00:00",
  "status": 401,
  "error": "Unauthorized",
  "message": "Full authentication is required to access this resource"
}
```

**Exemplo de Uso (cURL)**:
```bash
curl -u master@erp.com:Master@123 \
  http://localhost:8081/api/users/listAll
```

**Exemplo de Uso (JavaScript)**:
```javascript
const credentials = btoa('master@erp.com:Master@123');

fetch('http://localhost:8081/api/users/listAll', {
  method: 'GET',
  headers: {
    'Authorization': `Basic ${credentials}`
  }
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Erro:', error));
```

---

## Códigos de Status HTTP

| Código | Descrição | Quando Ocorre |
|--------|-----------|---------------|
| 200 | OK | Requisição bem-sucedida |
| 201 | Created | Usuário criado com sucesso |
| 400 | Bad Request | Dados inválidos na requisição |
| 401 | Unauthorized | Autenticação necessária ou falhou |
| 403 | Forbidden | Acesso negado (endpoint /create apenas para ADMIN) |
| 404 | Not Found | Endpoint não encontrado |
| 409 | Conflict | Email já existe |
| 500 | Internal Server Error | Erro interno do servidor |

---

## Autenticação HTTP Basic

### Como Funciona
A autenticação HTTP Basic envia credenciais no header `Authorization` usando codificação Base64.

### Formato
```
Authorization: Basic <base64(email:password)>
```

### Exemplo de Codificação
```javascript
// Email: joao@empresa.com
// Senha: MinhaSenha123
// String: joao@empresa.com:MinhaSenha123
// Base64: am9hb0BlbXByZXNhLmNvbTpNaW5oYVNlbmhhMTIz

const credentials = btoa('joao@empresa.com:MinhaSenha123');
// Resultado: am9hb0BlbXByZXNhLmNvbTpNaW5oYVNlbmhhMTIz
```

---

## Exemplos de Integração

### Python (requests)
```python
import requests
import base64

# Configuração
base_url = "http://localhost:8081"
email = "joao@empresa.com"
password = "MinhaSenha123"

# Codificar credenciais
credentials = base64.b64encode(f"{email}:{password}".encode()).decode()

# Headers
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {credentials}"
}

# Registrar usuário
def register_user(email, password, role):
    data = {
        "email": email,
        "password": password,
        "role": role
    }
    
    response = requests.post(
        f"{base_url}/api/users/register",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    
    return response.status_code, response.text

# Criar usuário (admin)
def create_user(email, password, role, admin_credentials):
    data = {
        "email": email,
        "password": password,
        "role": role
    }
    
    admin_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {admin_credentials}"
    }
    
    response = requests.post(
        f"{base_url}/api/users/create",
        json=data,
        headers=admin_headers
    )
    
    return response.status_code, response.text

# Listar usuários
def list_users():
    response = requests.get(
        f"{base_url}/api/users/listAll",
        headers=headers
    )
    
    return response.status_code, response.json()

# Exemplo de uso
status, result = register_user("maria@empresa.com", "Senha123", "USER")
print(f"Registro: {status} - {result}")

admin_creds = base64.b64encode("master@erp.com:Master@123".encode()).decode()
status, result = create_user("pedro@empresa.com", "Senha123", "USER", admin_creds)
print(f"Criação: {status} - {result}")

status, users = list_users()
print(f"Usuários: {status} - {users}")
```

### Java (HttpClient)
```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.Base64;

public class ERPClient {
    private static final String BASE_URL = "http://localhost:8081";
    private static final HttpClient client = HttpClient.newHttpClient();
    
    public static String registerUser(String email, String password, String role) throws Exception {
        String json = String.format(
            "{\"email\":\"%s\",\"password\":\"%s\",\"role\":\"%s\"}",
            email, password, role
        );
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + "/api/users/register"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        return response.body();
    }
    
    public static String createUser(String email, String password, String role, 
                                   String adminEmail, String adminPassword) throws Exception {
        String json = String.format(
            "{\"email\":\"%s\",\"password\":\"%s\",\"role\":\"%s\"}",
            email, password, role
        );
        
        String credentials = Base64.getEncoder()
            .encodeToString((adminEmail + ":" + adminPassword).getBytes());
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + "/api/users/create"))
            .header("Content-Type", "application/json")
            .header("Authorization", "Basic " + credentials)
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        return response.body();
    }
    
    public static String listUsers(String email, String password) throws Exception {
        String credentials = Base64.getEncoder()
            .encodeToString((email + ":" + password).getBytes());
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + "/api/users/listAll"))
            .header("Authorization", "Basic " + credentials)
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        return response.body();
    }
}
```

### PHP (cURL)
```php
<?php

class ERPClient {
    private $baseUrl = 'http://localhost:8081';
    
    public function registerUser($email, $password, $role) {
        $data = [
            'email' => $email,
            'password' => $password,
            'role' => $role
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->baseUrl . '/api/users/register');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return ['code' => $httpCode, 'response' => $response];
    }
    
    public function createUser($email, $password, $role, $adminEmail, $adminPassword) {
        $data = [
            'email' => $email,
            'password' => $password,
            'role' => $role
        ];
        
        $credentials = base64_encode($adminEmail . ':' . $adminPassword);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->baseUrl . '/api/users/create');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Basic ' . $credentials
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return ['code' => $httpCode, 'response' => $response];
    }
    
    public function listUsers($email, $password) {
        $credentials = base64_encode($email . ':' . $password);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->baseUrl . '/api/users/listAll');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Basic ' . $credentials
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return ['code' => $httpCode, 'response' => json_decode($response, true)];
    }
}

// Exemplo de uso
$client = new ERPClient();

// Registrar usuário
$result = $client->registerUser('pedro@empresa.com', 'Senha123', 'USER');
echo "Registro: " . $result['code'] . " - " . $result['response'] . "\n";

// Criar usuário (admin)
$result = $client->createUser('ana@empresa.com', 'Senha123', 'USER', 'master@erp.com', 'Master@123');
echo "Criação: " . $result['code'] . " - " . $result['response'] . "\n";

// Listar usuários
$users = $client->listUsers('master@erp.com', 'Master@123');
echo "Usuários: " . print_r($users, true) . "\n";

?>
```

---

## Testes com Postman

### Collection JSON
```json
{
  "info": {
    "name": "ERP API",
    "description": "Testes da API do Sistema ERP"
  },
  "item": [
    {
      "name": "Registrar Usuário",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"teste@exemplo.com\",\n  \"password\": \"123456\",\n  \"role\": \"USER\"\n}"
        },
        "url": {
          "raw": "http://localhost:8081/api/users/register",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["api", "users", "register"]
        }
      }
    },
    {
      "name": "Criar Usuário (Admin)",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          },
          {
            "key": "Authorization",
            "value": "Basic {{admin_credentials}}"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"novo@empresa.com\",\n  \"password\": \"123456\",\n  \"role\": \"USER\"\n}"
        },
        "url": {
          "raw": "http://localhost:8081/api/users/create",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["api", "users", "create"]
        }
      }
    },
    {
      "name": "Login",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "Authorization",
            "value": "Basic {{credentials}}"
          }
        ],
        "url": {
          "raw": "http://localhost:8081/api/users/login",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["api", "users", "login"]
        }
      }
    },
    {
      "name": "Listar Usuários",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "Authorization",
            "value": "Basic {{credentials}}"
          }
        ],
        "url": {
          "raw": "http://localhost:8081/api/users/listAll",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["api", "users", "listAll"]
        }
      }
    }
  ],
  "variable": [
    {
      "key": "credentials",
      "value": "bWFzdGVyQGVycC5jb206TWFzdGVyQDEyMw=="
    },
    {
      "key": "admin_credentials",
      "value": "bWFzdGVyQGVycC5jb206TWFzdGVyQDEyMw=="
    }
  ]
}
```

---

## Limitações Atuais

1. **Autenticação**: Apenas HTTP Basic (não JWT)
2. **Validação**: Validação básica de email único
3. **Roles**: Apenas ADMIN e USER
4. **Endpoints**: Operações básicas de usuário
5. **Segurança**: Sem rate limiting ou validação avançada
6. **Autorização**: Endpoint /create restrito apenas para ADMIN

---

## Próximas Versões

### v1.1 (Planejado)
- [ ] JWT Authentication
- [ ] Validação de entrada com Bean Validation
- [ ] Rate limiting
- [ ] Logs de auditoria
- [ ] Endpoints para atualização e exclusão de usuários

### v1.2 (Planejado)
- [ ] Gestão de produtos
- [ ] Controle de estoque
- [ ] Relatórios básicos
- [ ] Sistema de permissões mais granular

---

**Autor**: ThiagoMartins2001  
**Versão da API**: 1.0  
**Última Atualização**: Dezembro 2024
