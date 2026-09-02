# Processos de onboarding e offboarding

## 1. Objetivo

Este documento descreve o desenho dos processos de entrada (onboarding) e
saída (offboarding) de colaboradores da Nortada Logística no domínio
`nortada.local`, implementados pelos scripts
`03-Onboard-Users.ps1` e `04-Offboard-User.ps1`, a correr no Controlador de
Domínio `NORTADA-DC01` depois de a estrutura de OUs e grupos existir (ver
`03-estrutura-ou-grupos.md`) e de a política de auditoria estar ativa (ver
`04-politica-auditoria.md`), de forma a que os próprios eventos gerados por
estes processos fiquem registados e visíveis no SentryLens.

## 2. Onboarding: `03-Onboard-Users.ps1`

### 2.1. Origem dos dados

O script lê um ficheiro **`data/colaboradores.csv`** (caminho configurável
pelo parâmetro `-CaminhoCsv`, por omissão `data/colaboradores.csv`
relativo à pasta `scripts/`), com uma linha por colaborador a admitir.
Colunas usadas pelo script: `Nome`, `Apelido`, `Cargo`, `Departamento`,
`Gestor`, `Email`, `Telefone`, `TipoConta` (o CSV pode incluir ainda
`DataAdmissao` e `DepartamentoAnterior` como colunas informativas, não
processadas pela lógica do script). O `Departamento` de cada linha tem de
corresponder a um dos seis departamentos definidos em `01-arquitetura.md`
(Direção, Financeira, Recursos Humanos, IT, Marketing, Operações) quando
`TipoConta` é `normal`; para `TipoConta` `administrativa` ou `servico` o
script usa sempre uma OU fixa, independente do Departamento indicado na
linha (ver secção 2.2).

O script lê também **`data/rbac_baseline.json`** (parâmetro
`-CaminhoBaseline`, por omissão `data/rbac_baseline.json` relativo a
`scripts/`) para resolver os grupos de segurança de cada Cargo, e aceita
um parâmetro `-DomainDN` (por omissão `DC=nortada,DC=local`) para ancorar
as OUs de destino.

### 2.2. Passos do processo, por ordem

1. **Determinar o nome de utilizador (SamAccountName)**, a partir do Nome
   e Apelido normalizados (minúsculas, sem acentos), de acordo com o
   `TipoConta` da linha:
   - `normal`: `primeiro.ultimo` (por exemplo, Ana Pereira torna-se
     `ana.pereira`).
   - `administrativa`: `adm.primeiro.ultimo` (por exemplo,
     `adm.ana.pereira`).
   - `servico`: o próprio Nome/Apelido da linha já representa a
     identidade da conta de serviço, sem qualquer prefixo `adm.` (por
     exemplo, Nome=Svc, Apelido=Backup gera `svc.backup`).

   Se já existir uma conta com o `SamAccountName` calculado, o script não
   a recria: regista um aviso ("conta já existe, ignorado") e passa à
   linha seguinte, sem tentar gerar um nome alternativo nem um sufixo
   numérico.
2. **Determinar a OU de destino**, também de acordo com o `TipoConta`:
   - `normal`: sub-OU de `OU=Utilizadores` correspondente ao
     `Departamento` da linha (por exemplo,
     `OU=Financeira,OU=Utilizadores,OU=NORTADA,DC=nortada,DC=local`).
   - `administrativa`: sempre
     `OU=Contas-Administrativas,OU=NORTADA,DC=nortada,DC=local`,
     independentemente do Departamento indicado na linha.
   - `servico`: sempre `OU=Contas-Servico,OU=NORTADA,DC=nortada,DC=local`,
     independentemente do Departamento indicado na linha.
3. **Definir uma password inicial** gerada de forma aleatória e
   criptograficamente segura, construída diretamente como `SecureString`.
   Para contas `normal` e `administrativa`, é aplicada com
   `ChangePasswordAtLogon = $true`, obrigando à mudança no primeiro início
   de sessão. Contas de serviço (`TipoConta = servico`) ficam com
   `PasswordNeverExpires = $true` e sem `ChangePasswordAtLogon`, porque não
   há um utilizador humano para responder a um pedido de mudança de
   password interativo. A password nunca é escrita em texto simples em
   disco nem apresentada na saída do script (nem no log de execução, nem
   no CSV de auditoria do passo 6): a variável de texto simples
   intermédia, inevitável para construir o `SecureString` em PowerShell, é
   limpa da memória imediatamente a seguir a ser usada. A comunicação da
   password inicial ao colaborador fica, por isso, a cargo de um canal
   separado, fora do âmbito deste laboratório.
4. **Preencher os atributos do AD**:
   - `Department` = Departamento da linha do CSV.
   - `Title` = Cargo da linha do CSV.
   - `Manager` = referência ao objeto de utilizador do Gestor indicado
     (resolvido pelo script a partir do nome; se o gestor não for
     encontrado no AD, o script regista um aviso e continua sem falhar a
     criação da conta). Nomes de Gestor com mais de duas palavras usam
     apenas a primeira e a última palavra como primeiro nome e apelido
     para calcular o `SamAccountName` esperado do gestor.
   - `EmailAddress` = Email da linha do CSV, apenas quando a coluna vem
     preenchida; se vier vazia, o atributo não é definido (o script não
     constrói automaticamente um endereço a partir do nome).
   - `OfficePhone` = Telefone da linha do CSV, apenas quando a coluna vem
     preenchida.
5. **Adicionar aos grupos de segurança** de acordo com
   `data/rbac_baseline.json`, que materializa a matriz de RBAC descrita em
   `06-rbac.md`: o script procura o Cargo exato da linha nesse ficheiro.
   - Se o Cargo não constar do baseline, nenhum grupo é atribuído por
     omissão: o script regista um aviso claro para revisão manual do
     RH/IT, em vez de arriscar conceder acessos adivinhados a partir de um
     cargo parecido (decisão de segurança "fail closed").
   - Se o Cargo constar, o script adiciona a conta apenas aos
     `grupos_permitidos`, nunca aos `grupos_proibidos`, conforme o modelo
     AGDLP de `03-estrutura-ou-grupos.md`; uma entrada do baseline com o
     mesmo grupo simultaneamente em `grupos_permitidos` e
     `grupos_proibidos` é tratada como erro de configuração do baseline, e
     essa adição específica é recusada com erro registado, em vez de
     resolvida automaticamente.
6. **Registar a operação num log CSV de auditoria** em
   `scripts/logs/onboarding-<data>.csv` (colunas: DataHora, Utilizador,
   Departamento, Cargo, GruposAtribuidos, Resultado), além do log de
   execução em texto simples, também em `scripts/logs/`. Este log CSV
   serve de trilha de auditoria complementar aos eventos gerados no
   Security Event Log (Event ID 4720 e associados, ver
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

O script lê um ficheiro **`data/saidas.csv`** (parâmetro
`-CaminhoSaidas`, por omissão `data/saidas.csv` relativo à pasta
`scripts/`), com uma linha por colaborador a desligar. Colunas esperadas:
`Nome`, `Apelido`, `DataSaida` e `Motivo`. O `SamAccountName` a processar
não é lido diretamente de uma coluna `Utilizador`: é calculado a partir de
Nome e Apelido com a mesma normalização usada no onboarding (minúsculas,
sem acentos, `primeiro.ultimo`), para garantir consistência entre os dois
processos.

Em alternativa, o parâmetro `-Utilizador` permite indicar diretamente um
único `SamAccountName` a processar (por exemplo, `ana.pereira`), para um
offboarding pontual fora do ciclo normal do CSV (por exemplo, uma saída
urgente ainda não registada em `data/saidas.csv`); nesse caso,
`data/saidas.csv` não é lido. O parâmetro `-DomainDN` (por omissão
`DC=nortada,DC=local`) ancora as OUs usadas pelo script.

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
3. **Remover de todos os grupos de segurança a que a conta pertence**, com
   registo da lista completa (removidos e mantidos) num log CSV separado
   por utilizador, em `scripts/logs/offboarding-<utilizador>-<data>.csv`,
   incluindo os grupos globais e quaisquer grupos de domínio local a que a
   conta pertencesse diretamente. O grupo primário da conta (tipicamente
   "Domain Users") é sempre mantido, nunca removido: o Active Directory não
   permite remover o grupo primário de uma conta sem lhe atribuir antes
   outro grupo primário, uma troca que fica fora do âmbito deste script;
   esse grupo fica explicitamente registado no CSV de auditoria como
   "mantido (grupo primário)", para que a auditoria não interprete a sua
   presença como um esquecimento. Este registo é essencial para auditoria
   posterior: permite reconstruir exatamente que acessos a conta tinha no
   momento da saída, sem depender de a conta ainda estar em qualquer grupo
   no AD.
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

### 3.4. Conta administrativa associada

Além da conta indicada (seja pela linha do CSV, seja pelo parâmetro
`-Utilizador`), o script procura automaticamente uma eventual conta
administrativa associada à mesma pessoa, `adm.<utilizador>` (por exemplo,
`adm.rui.pinto` para `rui.pinto`). Se essa conta existir, o script
aplica-lhe exatamente o mesmo processo de offboarding de 5 passos descrito
na secção 3.2, pela mesma ordem. Este comportamento existe porque
desativar apenas a conta do dia a dia e deixar a conta administrativa
correspondente ativa seria uma falha grave de offboarding: a conta com
privilégios elevados (por exemplo, membro de `GG-IT-Admins`) ficaria
utilizável depois de a pessoa deixar a organização. Quando a conta
indicada já começa por `adm.`, o script não repete esta procura sobre si
própria.

### 3.5. Idempotência e o parâmetro `-Forcar`

O script deteta se uma conta já foi offboarded numa execução anterior
verificando duas condições em conjunto: a conta está desativada e o
atributo `Description` começa por "Saída em ". Quando ambas se verificam,
uma nova execução não repete os passos destrutivos (reposição de password,
remoção de grupos): regista apenas um aviso de confirmação, sem qualquer
alteração adicional. O parâmetro `-Forcar` permite repetir esses passos
destrutivos mesmo sobre uma conta já marcada como offboarded, para os
casos em que seja mesmo necessário reprocessá-la (por exemplo, suspeita de
que a password foi reposta manualmente depois do offboarding original).

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

Este documento foi afinado depois de os scripts `03-Onboard-Users.ps1` e
`04-Offboard-User.ps1` estarem finalizados, para que os nomes de
parâmetros, os caminhos de log e os comportamentos aqui descritos
correspondam exatamente à implementação real.
