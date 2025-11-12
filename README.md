# Sistema de Gerenciamento de Biblioteca

API RESTful para gerenciamento de empréstimos de livros em uma biblioteca, com controle de permissões para diferentes tipos de usuários.

##  Tecnologias

- **Node.js** + **Express** - Framework web
- **MySQL** - Banco de dados relacional
- **Sequelize** - ORM para Node.js
- **JWT** - Autenticação e autorização
- **bcryptjs** - Criptografia de senhas

##  Funcionalidades

### Bibliotecário
*  Cadastrar, atualizar e remover livros
*  Aprovar/rejeitar solicitações de empréstimos
*  Aprovar devoluções
*  Visualizar todos os empréstimos

### Leitor
*  Visualizar livros disponíveis
*  Solicitar empréstimos
*  Solicitar devoluções
*  Visualizar seus empréstimos

## 🛠️ Instalação

### 1. Clone o repositório e instale as dependências

```bash
npm install
```

### 2. Configure o banco de dados

Crie um banco de dados MySQL:

```sql
CREATE DATABASE biblioteca_db;
```

### 3. Configure as variáveis de ambiente

Copie o arquivo `.env.example` para `.env` e configure:

```bash
cp .env.example .env
```

Edite o arquivo `.env` com suas configurações:

```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=biblioteca_db
DB_USER=root
DB_PASSWORD=sua_senha

PORT=3000
NODE_ENV=development

JWT_SECRET=sua_chave_secreta_muito_segura_aqui
JWT_EXPIRES_IN=7d
```

### 4. Inicie o servidor

```bash
# Modo desenvolvimento 
npm run dev

# Modo produção
npm start
```

O servidor estará rodando em `http://localhost:3000`

## 📚 Documentação da API

### Autenticação

#### Registrar usuário
```http
POST /api/auth/register
Content-Type: application/json

{
  "nome": "João Silva",
  "email": "joao@email.com",
  "senha": "senha123",
  "tipo": "leitor",  // ou "bibliotecario"
  "telefone": "(11) 99999-9999",
  "endereco": "Rua Example, 123"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "joao@email.com",
  "senha": "senha123"
}

Response:
{
  "message": "Login realizado com sucesso!",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "nome": "João Silva",
    "email": "joao@email.com",
    "tipo": "leitor"
  }
}
```

#### Buscar perfil
```http
GET /api/auth/profile
Authorization: Bearer {token}
```

### Livros

#### Listar livros
```http
GET /api/books?titulo=&autor=&categoria=&disponivel=true
Authorization: Bearer {token}
```

#### Buscar livro por ID
```http
GET /api/books/:id
Authorization: Bearer {token}
```

#### Cadastrar livro (Bibliotecário)
```http
POST /api/books
Authorization: Bearer {token}
Content-Type: application/json

{
  "titulo": "O Senhor dos Anéis",
  "autor": "J.R.R. Tolkien",
  "isbn": "9788533613379",
  "editora": "Martins Fontes",
  "anoPublicacao": 1954,
  "categoria": "Fantasia",
  "quantidadeTotal": 5,
  "descricao": "Uma épica aventura...",
  "localizacao": "Estante A, Prateleira 3"
}
```

#### Atualizar livro (Bibliotecário)
```http
PUT /api/books/:id
Authorization: Bearer {token}
Content-Type: application/json

{
  "quantidadeTotal": 10
}
```

#### Remover livro (Bibliotecário)
```http
DELETE /api/books/:id
Authorization: Bearer {token}
```

### Empréstimos

#### Solicitar empréstimo (Leitor)
```http
POST /api/loans/request
Authorization: Bearer {token}
Content-Type: application/json

{
  "bookId": 1,
  "dataPrevistaDevolucao": "2025-11-17"
}
```

#### Listar meus empréstimos
```http
GET /api/loans/my-loans?status=emprestado
Authorization: Bearer {token}
```

#### Solicitar devolução (Leitor)
```http
PUT /api/loans/:id/return
Authorization: Bearer {token}
```

#### Listar todos os empréstimos (Bibliotecário)
```http
GET /api/loans?status=pendente
Authorization: Bearer {token}
```

#### Aprovar empréstimo (Bibliotecário)
```http
PUT /api/loans/:id/approve
Authorization: Bearer {token}
```

#### Rejeitar empréstimo (Bibliotecário)
```http
PUT /api/loans/:id/reject
Authorization: Bearer {token}
Content-Type: application/json

{
  "observacoes": "Livro não disponível no momento"
}
```

#### Aprovar devolução (Bibliotecário)
```http
PUT /api/loans/:id/approve-return
Authorization: Bearer {token}
```

## 📊 Estrutura do Banco de Dados

### Tabela: usuarios
- id (PK)
- nome
- email (unique)
- senha (hash)
- tipo (enum: 'bibliotecario', 'leitor')
- telefone
- endereco
- ativo
- createdAt, updatedAt

### Tabela: livros
- id (PK)
- titulo
- autor
- isbn (unique)
- editora
- anoPublicacao
- categoria
- quantidadeTotal
- quantidadeDisponivel
- descricao
- localizacao
- createdAt, updatedAt

### Tabela: emprestimos
- id (PK)
- userId (FK)
- bookId (FK)
- dataEmprestimo
- dataPrevistaDevolucao
- dataDevolucao
- status (enum: 'pendente', 'aprovado', 'emprestado', 'devolvido', 'rejeitado')
- observacoes
- createdAt, updatedAt

## 🔐 Fluxo de Empréstimo

1. **Leitor** solicita empréstimo → Status: `pendente`
2. **Bibliotecário** aprova → Status: `emprestado`
3. **Leitor** solicita devolução → Status: `devolvido`
4. **Bibliotecário** aprova devolução → Livro volta ao estoque

## 🧪 Testando a API

Você pode usar ferramentas como:
- **Postman**
- **Insomnia**
- **Thunder Client** (extensão VS Code)
- **cURL**

Exemplo com cURL:
```bash
# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"joao@email.com","senha":"senha123"}'

# Listar livros (use o token recebido)
curl -X GET http://localhost:3000/api/books \
  -H "Authorization: Bearer SEU_TOKEN_AQUI"
```

##  Estrutura do Projeto

```
biblioteca_back/
├── src/
│   ├── config/
│   │   └── database.js
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── bookController.js
│   │   └── loanController.js
│   ├── middlewares/
│   │   └── auth.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Book.js
│   │   ├── Loan.js
│   │   └── index.js
│   ├── routes/
│   │   ├── authRoutes.js
│   │   ├── bookRoutes.js
│   │   └── loanRoutes.js
│   └── server.js
├── .env
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

##  Equipe

Este projeto foi desenvolvido para a disciplina de [Desenvolvimento Web].

## 📝 Licença

ISC
# biblioteca_back
