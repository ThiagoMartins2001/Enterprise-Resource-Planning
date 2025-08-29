# Documentação da API - Sistema ERP

## Autor
**ThiagoMartins2001**

## Informações Gerais

- **Base URL**: `http://localhost:8081`
- **Content-Type**: `application/json`
- **Autenticação**: HTTP Basic Authentication
- **Versão**: 1.0

## Endpoints Disponíveis

### 1. Criação de Usuário (Admin)

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

### 5. Exclusão de Usuário (Admin)

#### DELETE /api/users/delete/{email}
Remove um usuário do sistema por email (apenas para administradores).

**URL**: `http://localhost:8081/api/users/delete/{email}`

**Método**: `DELETE`

**Autenticação**: Obrigatória (apenas ADMIN)

**Headers**:
```
Authorization: Basic <base64(email:password)>
```

**Parâmetros**:
- `email` (string, obrigatório): Email do usuário a ser removido (path variable)

**Respostas**:

**Sucesso (200 OK)**:
```json
"User deleted successfully!"
```

**Erro - Usuário não encontrado (404 Not Found)**:
```json
"User not found"
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
curl -X DELETE \
  -H "Authorization: Basic bWFzdGVyQGVycC5jb206TWFzdGVyQDEyMw==" \
  http://localhost:8081/api/users/delete/maria@empresa.com
```

**Exemplo de Uso (JavaScript)**:
```javascript
const credentials = btoa('master@erp.com:Master@123');

fetch('http://localhost:8081/api/users/delete/maria@empresa.com', {
  method: 'DELETE',
  headers: {
    'Authorization': `Basic ${credentials}`
  }
})
.then(response => response.text())
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
| 403 | Forbidden | Acesso negado (endpoints /create e /delete apenas para ADMIN) |
| 404 | Not Found | Endpoint não encontrado ou usuário não encontrado |
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

# Registrar usuário (removido - endpoint não existe mais)
# def register_user(email, password, role):
#     data = {
#         "email": email,
#         "password": password,
#         "role": role
#     }
#     
#     response = requests.post(
#         f"{base_url}/api/users/register",
#         json=data,
#         headers={"Content-Type": "application/json"}
#     )
#     
#     return response.status_code, response.text

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

# Excluir usuário (admin)
def delete_user(email, admin_credentials):
    response = requests.delete(
        f"{base_url}/api/users/delete/{email}",
        headers={"Authorization": f"Basic {admin_credentials}"}
    )
    
    return response.status_code, response.text

# Exemplo de uso
# status, result = register_user("maria@empresa.com", "Senha123", "USER")
# print(f"Registro: {status} - {result}")

admin_creds = base64.b64encode("master@erp.com:Master@123".encode()).decode()
status, result = create_user("pedro@empresa.com", "Senha123", "USER", admin_creds)
print(f"Criação: {status} - {result}")

status, users = list_users()
print(f"Usuários: {status} - {users}")

status, result = delete_user("pedro@empresa.com", admin_creds)
print(f"Exclusão: {status} - {result}")
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
    
    // Método registerUser removido - endpoint não existe mais
    // public static String registerUser(String email, String password, String role) throws Exception {
    //     String json = String.format(
    //         "{\"email\":\"%s\",\"password\":\"%s\",\"role\":\"%s\"}",
    //         email, password, role
    //     );
    //     
    //     HttpRequest request = HttpRequest.newBuilder()
    //         .uri(URI.create(BASE_URL + "/api/users/register"))
    //         .header("Content-Type", "application/json")
    //         .POST(HttpRequest.BodyPublishers.ofString(json))
    //         .build();
    //     
    //     HttpResponse<String> response = client.send(request, 
    //         HttpResponse.BodyHandlers.ofString());
    //     
    //     return response.body();
    // }
    
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
    
    public static String deleteUser(String email, String adminEmail, String adminPassword) throws Exception {
        String credentials = Base64.getEncoder()
            .encodeToString((adminEmail + ":" + adminPassword).getBytes());
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + "/api/users/delete/" + email))
            .header("Authorization", "Basic " + credentials)
            .DELETE()
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
    
    // Método registerUser removido - endpoint não existe mais
    // public function registerUser($email, $password, $role) {
    //     $data = [
    //         'email' => $email,
    //         'password' => $password,
    //         'role' => $role
    //     ];
    //     
    //     $ch = curl_init();
    //     curl_setopt($ch, CURLOPT_URL, $this->baseUrl . '/api/users/register');
    //     curl_setopt($ch, CURLOPT_POST, true);
    //     curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    //     curl_setopt($ch, CURLOPT_HTTPHEADER, [
    //         'Content-Type: application/json'
    //     ]);
    //     curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    //     
    //     $response = curl_exec($ch);
    //     $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    //     curl_close($ch);
    //     
    //     return ['code' => $httpCode, 'response' => $response];
    // }
    
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
    
    public function deleteUser($email, $adminEmail, $adminPassword) {
        $credentials = base64_encode($adminEmail . ':' . $adminPassword);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->baseUrl . '/api/users/delete/' . $email);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Basic ' . $credentials
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return ['code' => $httpCode, 'response' => $response];
    }
}

// Exemplo de uso
$client = new ERPClient();

// Registrar usuário (removido - endpoint não existe mais)
// $result = $client->registerUser('pedro@empresa.com', 'Senha123', 'USER');
// echo "Registro: " . $result['code'] . " - " . $result['response'] . "\n";

// Criar usuário (admin)
$result = $client->createUser('ana@empresa.com', 'Senha123', 'USER', 'master@erp.com', 'Master@123');
echo "Criação: " . $result['code'] . " - " . $result['response'] . "\n";

// Listar usuários
$users = $client->listUsers('master@erp.com', 'Master@123');
echo "Usuários: " . print_r($users, true) . "\n";

// Excluir usuário (admin)
$result = $client->deleteUser('ana@empresa.com', 'master@erp.com', 'Master@123');
echo "Exclusão: " . $result['code'] . " - " . $result['response'] . "\n";

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
    },
    {
      "name": "Excluir Usuário (Admin)",
      "request": {
        "method": "DELETE",
        "header": [
          {
            "key": "Authorization",
            "value": "Basic {{admin_credentials}}"
          }
        ],
        "url": {
          "raw": "http://localhost:8081/api/users/delete/{{email}}",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["api", "users", "delete", "{{email}}"]
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
    },
    {
      "key": "email",
      "value": "teste@empresa.com"
    }
  ]
}
```

---

## Limitações Atuais

1. **Autenticação**: Apenas HTTP Basic (não JWT)
2. **Validação**: Validação básica de email único
3. **Roles**: Apenas ADMIN e USER
4. **Endpoints**: Operações básicas de usuário (CRUD parcial)
5. **Segurança**: Sem rate limiting ou validação avançada
6. **Autorização**: Endpoints /create e /delete restritos apenas para ADMIN
7. **Registro**: Sem endpoint público de registro de usuários

---

## Próximas Versões

### v1.1 (Planejado)
- [ ] JWT Authentication
- [ ] Validação de entrada com Bean Validation
- [ ] Rate limiting
- [ ] Logs de auditoria
- [ ] Endpoint para atualização de usuários
- [ ] Endpoint público de registro de usuários

### v1.2 (Planejado)
- [ ] Gestão de produtos
- [ ] Controle de estoque
- [ ] Relatórios básicos
- [ ] Sistema de permissões mais granular

---

**Autor**: ThiagoMartins2001  
**Versão da API**: 1.0  
**Última Atualização**: Dezembro 2024
