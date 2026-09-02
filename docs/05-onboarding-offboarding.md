# Processos de onboarding e offboarding

## 1. Objetivo

Este documento descreve o desenho dos processos de entrada (onboarding) e
saída (offboarding) de colaboradores da Nortada Logística no domínio
`nortada.local`, a implementar pelos scripts futuros
`03-Onboard-Users.ps1` e `04-Offboard-User.ps1`, a correr no Controlador de
Domínio `NORTADA-DC01` depois de a estrutura de OUs e grupos existir (ver
`03-estrutura-ou-grupos.md`) e de a política de auditoria estar ativa (ver
`04-politica-auditoria.md`), de forma a que os próprios eventos gerados por
estes processos fiquem registados e visíveis no SentryLens.

## 2. Onboarding: `03-Onboard-Users.ps1`

### 2.1. Origem dos dados

O script lê um ficheiro **`data/colaboradores.csv`**, a criar num passo
posterior fora do âmbito deste documento, com uma linha por colaborador a
admitir. Colunas previstas: `Nome`, `Apelido`, `Departamento`, `Cargo`,
`Gestor`, `Telefone`, `Email` (ou construído a partir do nome se a coluna
vier vazia). O `Departamento` de cada linha tem de corresponder a um dos
seis departamentos definidos em `01-arquitetura.md` (Direção, Financeira,
Recursos Humanos, IT, Marketing, Operações), para que o script saiba em
que sub-OU de `OU=Utilizadores` criar a conta.

### 2.2. Passos do processo, por ordem

1. **Determinar o nome de utilizador**, seguindo a convenção
   `primeiro.ultimo` em minúsculas (por exemplo, Ana Pereira torna-se
   `ana.pereira`). O script trata colisões (duas pessoas com o mesmo nome e
   apelido) acrescentando um número sequencial (`ana.pereira2`), e regista
   esse caso no log de execução para revisão manual.
2. **Criar a conta** na sub-OU de `OU=Utilizadores` correspondente ao
   `Departamento` da linha (por exemplo, `OU=Financeira,OU=Utilizadores,
   OU=NORTADA,DC=nortada,DC=local`).
3. **Definir uma password inicial** gerada de forma aleatória e
   suficientemente complexa, com a flag `-ChangePasswordAtLogon $true`, de
   forma a obrigar à mudança de password no primeiro início de sessão. A
   password inicial nunca é reutilizada entre colaboradores nem gravada em
   texto simples num local persistente: é apresentada uma única vez na
   saída do script (ou entregue por um canal separado fora do âmbito deste
   laboratório) para comunicação ao colaborador.
4. **Preencher os atributos do AD**:
   - `Department` = Departamento da linha do CSV.
   - `Title` = Cargo da linha do CSV.
   - `Manager` = referência ao objeto de utilizador do Gestor indicado
     (resolvido pelo script a partir do nome; se o gestor não for
     encontrado no AD, o script regista um aviso e continua sem falhar a
     criação da conta).
   - `EmailAddress` = Email da linha do CSV, ou construído como
     `primeiro.ultimo@nortada.local` se a coluna vier vazia.
   - `OfficePhone` = Telefone da linha do CSV.
5. **Adicionar aos grupos de segurança** correspondentes ao Cargo,
   segundo a matriz de RBAC descrita em `06-rbac.md` (por exemplo, um
   colaborador com Cargo "Técnico de Suporte IT" é adicionado ao grupo
   global `GG-IT-Suporte`, nunca diretamente a um grupo de domínio local,
   conforme o modelo AGDLP de `03-estrutura-ou-grupos.md`).
6. **Registar a operação num log CSV** (por exemplo,
   `logs/onboarding-<data>.csv`), com pelo menos: data e hora, utilizador
   criado, departamento, cargo, grupos atribuídos, e resultado (sucesso ou
   erro com motivo). Este log serve de trilha de auditoria complementar aos
   eventos gerados no Security Event Log (Event ID 4720 e associados, ver
   `04-politica-auditoria.md`).

### 2.3. Suporte a `-WhatIf`

O script implementa o parâmetro comum `-WhatIf` do PowerShell (via
`SupportsShouldProcess`), de forma a que seja possível correr
`03-Onboard-Users.ps1 -WhatIf` contra o `colaboradores.csv` e obter uma
pré-visualização de todas as contas, atributos e adições a grupos que
seriam criados, sem alterar de facto o Active Directory. Isto permite
validar o conteúdo do CSV (departamentos mal escritos, gestores
inexistentes, cargos sem mapeamento em `06-rbac.md`) antes de qualquer
escrita real, particularmente relevante num processo que cria contas com
password e pertença a grupos em lote.

## 3. Offboarding: `04-Offboard-User.ps1`

### 3.1. Origem dos dados

O script lê um ficheiro **`data/saidas.csv`**, também a criar num passo
posterior, com uma linha por colaborador a desligar. Coluna mínima
esperada: `Utilizador` (o `sAMAccountName`, por exemplo `ana.pereira`), e
opcionalmente `DataSaida` e `Motivo` para registo.

### 3.2. Ordem de segurança do processo

O offboarding segue uma ordem deliberada, pensada para minimizar a janela
de tempo em que uma conta de um ex-colaborador continua a poder ser usada
ou continua com sessões ativas, antes de qualquer outra limpeza:

1. **Desativar a conta imediatamente** (`Disable-ADAccount`). Este é
   sempre o primeiro passo, executado antes de qualquer outra alteração,
   porque impede novos logons a partir do momento em que o script corre,
   independentemente de os passos seguintes ainda não terem terminado.
2. **Terminar sessões ativas e repor a password para um valor aleatório**
   (revogação de tokens). Desativar a conta não termina sessões Kerberos já
   estabelecidas nem invalida tokens de acesso já emitidos; repor a
   password para um valor aleatório desconhecido invalida credenciais
   em cache e força a reautenticação a falhar em qualquer sessão ou
   aplicação que ainda dependa da password antiga. Este passo corre logo a
   seguir à desativação, antes de qualquer alteração a grupos, para que uma
   sessão ainda ativa não seja aproveitada para reverter os passos
   seguintes.
3. **Remover de todos os grupos de segurança**, com registo da lista
   completa de grupos removidos num log CSV separado (por exemplo,
   `logs/offboarding-<utilizador>-<data>.csv`), incluindo os grupos globais
   e quaisquer grupos de domínio local a que a conta pertencesse
   diretamente. Este registo é essencial para auditoria posterior: permite
   reconstruir exatamente que acessos a conta tinha no momento da saída,
   sem depender de a conta ainda estar em qualquer grupo no AD.
4. **Mover a conta para `OU=Contas-Desativadas`**, fora das OUs de
   departamento ativas, de forma a que a conta deixe de aparecer em
   listagens, GPOs ou relatórios pensados para colaboradores em atividade.
5. **Marcar a descrição da conta com a data de saída** (atributo
   `Description`, por exemplo "Saída em 2026-09-02, ver
   logs/offboarding-ana.pereira-2026-09-02.csv"), para que qualquer pessoa
   a inspecionar a conta mais tarde (incluindo o próprio utilizador do
   script, meses depois) veja de imediato o estado e a razão sem ter de
   cruzar múltiplos ficheiros de log.

### 3.3. Porque a conta nunca é eliminada

O processo de offboarding desativa e isola a conta, mas nunca a elimina
(`Remove-ADObject` ou equivalente nunca é chamado sobre uma conta de
utilizador que tenha existido em produção). Motivos:

- **Retenção para investigação forense.** Se mais tarde surgir uma
  necessidade de investigar atividade passada desse utilizador (por
  exemplo, no âmbito de uma auditoria de segurança ou de uma suspeita de
  incidente anterior à saída), a conta continua a existir no AD como
  referência, mesmo desativada, o que preserva o `SID` e a associação a
  eventos históricos já registados no SentryLens.
- **Preservação da propriedade de ficheiros e caixa de correio.** No
  Windows, a propriedade (owner) de ficheiros e outros objetos é associada
  ao `SID` da conta, não ao nome. Eliminar a conta transforma esses
  registos de propriedade num `SID` órfão, não resolúvel a um nome,
  dificultando a reatribuição de ficheiros a outro responsável ou o acesso
  administrativo a uma caixa de correio antiga. Manter a conta (desativada)
  preserva essa referência resolúvel.
- **Eliminação é irreversível, desativação não.** Se surgir um erro no
  processo (por exemplo, o CSV de saídas incluir por engano um
  colaborador que na realidade não saiu), reverter uma desativação é
  imediato (`Enable-ADAccount` e devolução aos grupos a partir do log de
  auditoria do passo 3). Reverter uma eliminação de conta no AD é, na
  prática, impossível sem recorrer a uma restauração de sistema (tombstone
  reanimation, com limitações e apenas dentro da janela de retenção do
  tombstone), o que é desproporcionado para corrigir um erro de processo.

A eliminação definitiva de contas antigas em `OU=Contas-Desativadas`, se
alguma vez vier a ser necessária por política de retenção de dados, é uma
decisão de negócio distinta, tomada e executada manualmente e fora do
âmbito automatizado destes scripts.

## 4. Relação com os outros documentos

- Os grupos atribuídos no passo 5 do onboarding e removidos no passo 3 do
  offboarding seguem a matriz de cargo para grupo definida em
  `06-rbac.md`.
- Os Event IDs gerados por estes dois scripts (4720, 4722, 4725, 4726,
  4738, 4728, 4729, 4732, 4733, entre outros) só ficam disponíveis para o
  Wazuh e para o SentryLens porque a Advanced Audit Policy descrita em
  `04-politica-auditoria.md` está ativa no DC.
- A estrutura de OUs (`OU=Contas-Desativadas`, sub-OUs de
  `OU=Utilizadores` por departamento) usada por estes dois scripts está
  definida em `03-estrutura-ou-grupos.md`.
