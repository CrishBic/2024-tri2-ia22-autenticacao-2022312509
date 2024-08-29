#2024-tri2-ia22-autenticação-2022312509

# Autenticação de Usuários (single server)

Claro! Vamos falar sobre autenticação de usuários em um cenário de servidor único (single server).

### O que é Autenticação de Usuários?

Autenticação de usuários é o processo de verificar a identidade de um usuário antes de permitir que ele acesse um sistema ou recurso. É um passo fundamental para garantir que apenas usuários autorizados possam acessar informações ou funcionalidades específicas.

### Cenário de Servidor Único

Em um ambiente de servidor único, todas as operações, como autenticação, armazenamento de dados e processamento, ocorrem em um único servidor. Isso simplifica a arquitetura, mas também traz alguns desafios em termos de escalabilidade e segurança.

### Como Funciona a Autenticação em um Servidor Único

1. **Cadastro do Usuário**: 
   - O usuário se cadastra fornecendo suas credenciais, como um nome de usuário e senha.
   - O servidor armazena essas credenciais de forma segura. Normalmente, as senhas são armazenadas como hashes (uma forma criptografada da senha) para evitar que senhas reais sejam comprometidas.

2. **Login do Usuário**: 
   - O usuário tenta fazer login fornecendo suas credenciais.
   - O servidor recebe essas credenciais e verifica se elas correspondem aos dados armazenados. Se a senha fornecida corresponder ao hash armazenado, a autenticação é bem-sucedida.

3. **Sessões**:
   - Após a autenticação bem-sucedida, o servidor cria uma sessão para o usuário. Isso geralmente envolve gerar um token de sessão ou um cookie que identifica o usuário em futuras requisições.
   - O token é enviado ao cliente e é usado em todas as requisições subsequentes para verificar se o usuário está autenticado.

4. **Controle de Acesso**:
   - Com o usuário autenticado, o servidor pode aplicar controles de acesso baseados nas permissões do usuário, decidindo o que ele pode e não pode fazer no sistema.

5. **Logout**:
   - Quando o usuário decide sair, o servidor pode invalidar o token de sessão ou o cookie, efetivamente desconectando o usuário.

### Aspectos de Segurança

- **Hashing de Senhas**: Em vez de armazenar senhas em texto claro, o servidor armazena uma versão criptografada da senha. Algoritmos como bcrypt ou Argon2 são recomendados para hashing de senhas.
  
- **Proteção contra Ataques**: Medidas como bloqueio de conta após múltiplas tentativas de login falhadas e uso de CAPTCHA podem ajudar a proteger contra ataques de força bruta.

- **Comunicação Segura**: Usar HTTPS para criptografar a comunicação entre o cliente e o servidor é crucial para evitar que credenciais sejam interceptadas.

### Desvantagens de um Servidor Único

- **Escalabilidade**: Um servidor único pode enfrentar limitações de capacidade e desempenho à medida que o número de usuários cresce.

- **Ponto Único de Falha**: Se o servidor falhar, o serviço pode ficar indisponível. Backup e estratégias de recuperação de desastres são importantes para mitigar isso.

- **Segurança**: Todos os dados estão centralizados em um único lugar, o que pode ser um alvo atrativo para atacantes. Medidas de segurança robustas são essenciais.

Em resumo, a autenticação de usuários em um servidor único é um processo que envolve a verificação de credenciais, a gestão de sessões e a implementação de controles de acesso, tudo em um único servidor. A segurança e a eficiência desse sistema dependem da implementação cuidadosa das práticas recomendadas.

## Autenticação VS Autorização

Claro, vamos explorar as diferenças entre autenticação e autorização. Ambos são conceitos fundamentais na segurança de sistemas, mas servem a propósitos distintos.

### Autenticação

**O que é**: 
Autenticação é o processo de verificar a identidade de um usuário ou entidade. É a primeira etapa para garantir que um usuário é quem ele diz ser.

**Como Funciona**:
1. **Entrada de Credenciais**: O usuário fornece suas credenciais (por exemplo, nome de usuário e senha) para o sistema.
2. **Verificação**: O sistema verifica essas credenciais comparando-as com as informações armazenadas. Se as credenciais estiverem corretas, o usuário é autenticado.

**Objetivo**: Garantir que o usuário é quem afirma ser.

**Exemplos**:
- **Login em um site**: Usuário digita um nome de usuário e uma senha. O sistema verifica e confirma a identidade.
- **Autenticação de dois fatores (2FA)**: Além da senha, o sistema requer um código temporário enviado para o telefone do usuário.

### Autorização

**O que é**: 
Autorização é o processo de determinar quais recursos ou operações um usuário autenticado pode acessar ou executar. Após a autenticação, o sistema verifica o nível de permissão do usuário.

**Como Funciona**:
1. **Verificação de Permissões**: Após a autenticação, o sistema consulta suas políticas de autorização para determinar quais recursos o usuário pode acessar e quais ações ele pode executar.
2. **Controle de Acesso**: O sistema aplica essas permissões para permitir ou negar o acesso a diferentes partes do sistema.

**Objetivo**: Garantir que um usuário autenticado só possa acessar os recursos e executar as operações que tem permissão para.

**Exemplos**:
- **Controle de Acesso a Arquivos**: Após fazer login, um usuário pode ter acesso apenas a certos arquivos com base em seu papel ou nível de acesso.
- **Permissões de Funções em um Sistema**: Um administrador pode criar e modificar usuários, enquanto um usuário comum só pode visualizar informações.

### Resumindo as Diferenças

- **Autenticação**: "Quem é você?" — Confirma a identidade do usuário.
  - **Pergunta**: "Você é realmente o usuário X?"
  - **Foco**: Identidade.

- **Autorização**: "O que você pode fazer?" — Define o que o usuário pode acessar ou fazer.
  - **Pergunta**: "Quais recursos ou operações o usuário X tem permissão para acessar?"
  - **Foco**: Permissões e acesso.

### Relação Entre os Dois

- **Autenticação** deve ocorrer antes da **autorização**. Você precisa saber quem é o usuário (autenticação) antes de decidir o que ele pode fazer (autorização).
- Um sistema de segurança bem projetado implementa ambos os processos para garantir que apenas usuários autenticados tenham acesso aos recursos apropriados e possam realizar apenas as ações permitidas.

Espero que isso ajude a esclarecer as diferenças entre autenticação e autorização! Se precisar de mais detalhes ou tiver outras dúvidas, sinta-se à vontade para perguntar.

## Autenticação com Token (JWT)

Claro! Vamos explorar a autenticação com tokens, focando no JSON Web Token (JWT), que é uma forma popular e eficiente de gerenciar a autenticação e a troca de informações de segurança entre partes.

### O que é JWT?

JSON Web Token (JWT) é um padrão aberto (RFC 7519) que define um método compacto e auto-suficiente para transmitir informações seguras entre as partes como um objeto JSON. JWTs são amplamente usados para autenticação e troca de informações em sistemas web.

### Estrutura de um JWT

Um JWT é composto por três partes principais, cada uma codificada em Base64Url e separada por pontos (.). Aqui está a estrutura básica:

1. **Header (Cabeçalho)**:
   - Contém informações sobre como o token é codificado e o tipo de token.
   - Normalmente inclui o algoritmo de assinatura (por exemplo, `HS256` para HMAC SHA-256).

   Exemplo de um cabeçalho JSON:
   ```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```

2. **Payload (Carga Útil)**:
   - Contém as declarações (claims). As claims são informações sobre um usuário e outras meta-informações. Existem três tipos de claims:
     - **Registered Claims**: Claims padrão como `iss` (emissor), `exp` (expiração), `sub` (assunto), etc.
     - **Public Claims**: Claims definidos por você ou pela comunidade. Devem ser registrados para evitar conflitos.
     - **Private Claims**: Claims personalizados entre as partes envolvidas que não são definidos ou registrados.

   Exemplo de uma carga útil JSON:
   ```json
   {
     "sub": "1234567890",
     "name": "John Doe",
     "admin": true
   }
   ```

3. **Signature (Assinatura)**:
   - Para criar a assinatura, você precisa codificar o cabeçalho e a carga útil, e então usar uma chave secreta e o algoritmo especificado para gerar a assinatura.
   - A assinatura garante que o token não foi alterado.

   Exemplo de como criar a assinatura com HMAC SHA-256:
   ```plaintext
   HMACSHA256(
     base64UrlEncode(header) + "." +
     base64UrlEncode(payload),
     secret)
   ```

### Como Funciona a Autenticação com JWT

1. **Usuário Faz Login**:
   - O usuário envia suas credenciais (por exemplo, nome de usuário e senha) para o servidor.

2. **Servidor Autentica o Usuário**:
   - O servidor verifica as credenciais. Se forem válidas, o servidor gera um JWT contendo informações relevantes (como o ID do usuário e o papel) e o retorna ao cliente.

3. **Cliente Armazena o JWT**:
   - O cliente armazena o JWT (geralmente em armazenamento local ou cookies).

4. **Cliente Faz Requisições Autenticadas**:
   - Em futuras requisições, o cliente inclui o JWT no cabeçalho da requisição (geralmente no cabeçalho `Authorization` com o esquema `Bearer`).

5. **Servidor Verifica o JWT**:
   - O servidor recebe o JWT, verifica a assinatura e a validade do token, e então decodifica as informações do payload.
   - Se o token for válido, o servidor permite o acesso aos recursos solicitados com base nas informações do token.

### Vantagens do JWT

- **Escalabilidade**: Como o JWT contém todas as informações necessárias, não é necessário consultar um banco de dados para cada requisição.
- **Descentralização**: Ideal para sistemas distribuídos, pois a autenticação pode ser verificada sem necessidade de um servidor centralizado de sessões.
- **Segurança**: A assinatura garante que o token não foi alterado. Além disso, JWTs podem ser configurados para expirar após um período específico.

### Considerações de Segurança

- **Manter a Chave Secreta Segura**: A segurança da assinatura do JWT depende da proteção da chave secreta.
- **Usar HTTPS**: Sempre transmita JWTs sobre HTTPS para evitar que sejam interceptados.
- **Gerenciar a Expiração**: Configure um tempo de expiração apropriado para o token para reduzir o risco de uso indevido.

### Exemplo Prático

Aqui está um exemplo de como um JWT pode ser representado:

1. **Cabeçalho Codificado**:
   ```plaintext
   eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9
   ```

2. **Carga Útil Codificada**:
   ```plaintext
   eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0
   ```

3. **Assinatura Codificada**:
   ```plaintext
   7fI2gVu6pVZ-zY4A7tyfoH3zfnk_h4RjKTe4sdXMQZk
   ```

4. **JWT Completo**:
   ```plaintext
   eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0.7fI2gVu6pVZ-zY4A7tyfoH3zfnk_h4RjKTe4sdXMQZk
   ```

Espero que essa explicação tenha ajudado a entender como a autenticação com JWT funciona! Se você tiver mais perguntas ou precisar de mais detalhes, estou aqui para ajudar.

## Projeto (Objeto de Estudos)

...
