# api_login_py
## 🔐 Tela de Autenticação com FastAPI

Este projeto é uma API simples de autenticação utilizando **FastAPI** e **SQLite**, com suporte a **registro de usuários**, **login com geração de JWT** e **testes automatizados** com `pytest`.

### ✨ Funcionalidades

- Registro de novos usuários
- Login com validação de senha
- Geração de token JWT para autenticação
- Hash de senhas com Bcrypt
- Armazenamento de dados com SQLite
- Testes unitários e de integração usando `pytest` + `TestClient`

---

### 🚀 Como rodar o projeto

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/seu-repositorio.git
   cd seu-repositorio
   ```

2. Instale as dependências:
   ```bash
   pip install fastapi uvicorn sqlalchemy passlib[bcrypt] python-jose pytest
   ```

3. Inicie o servidor:
   ```bash
   uvicorn nome_do_arquivo:app --reload
   ```

4. Acesse a documentação interativa:
   ```
   http://127.0.0.1:8000/docs
   ```

---

### 🧪 Executar os testes

```bash
pytest nome_do_arquivo.py
```

---

### 💡 Estrutura do projeto

- `/register` – Endpoint para criar novo usuário
- `/login` – Endpoint para autenticar e receber token JWT

---

### 🛡️ Segurança

- Senhas são armazenadas com hash seguro (bcrypt)
- JWTs são utilizados para autenticação
- Proteção contra login inválido e usuários duplicados
