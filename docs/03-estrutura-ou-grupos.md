# Estrutura de Unidades Organizacionais e modelo de grupos (AGDLP)

## 1. Objetivo

Este documento descreve a árvore de Unidades Organizacionais (OUs) e o
modelo de grupos de segurança do domínio `nortada.local`, criados pelos
scripts `01-New-OuStructure.ps1` (estrutura de OUs) e
`02-New-SecurityGroups.ps1` (grupos de segurança), ambos a correr no
Controlador de Domínio `NORTADA-DC01` depois de este estar promovido
(ver `02-instalacao-dc.md`).

## 2. Árvore de Unidades Organizacionais

Estrutura a criar sob o domínio `nortada.local` (representada como
distinguished name relativo à raiz do domínio):

```
OU=NORTADA
  OU=Utilizadores
    OU=Direcao
    OU=Financeira
    OU=RecursosHumanos
    OU=IT
    OU=Marketing
    OU=Operacoes
  OU=Contas-Administrativas
  OU=Grupos
    OU=Seguranca
    OU=Distribuicao
  OU=Computadores
    OU=Servidores
    OU=Estacoes
  OU=Contas-Servico
  OU=Contas-Desativadas
```

Todas as OUs ficam sob uma OU de topo única, `OU=NORTADA`, em vez de
diretamente sob a raiz do domínio. Isto isola todos os objetos geridos por
este laboratório de objetos predefinidos do AD (como `Users` e `Computers`,
os contentores nativos), facilita aplicar GPOs a um único ponto da árvore
e simplifica uma eventual exportação ou remoção completa da estrutura.

### 2.1. Lógica de cada OU

- **OU=Utilizadores**: contentor de topo para todas as contas de utilizador
  normais (`primeiro.ultimo`), organizadas por departamento em sub-OUs.
  Separar por departamento permite aplicar GPOs específicas por
  departamento (por exemplo, políticas de mapeamento de unidades de rede ou
  restrições de aplicações diferentes para Financeira e para Marketing) e
  delegar permissões administrativas de forma granular (por exemplo, dar a
  um gestor de Recursos Humanos permissão para repor passwords apenas na OU
  `RecursosHumanos`).
  - **Direcao, Financeira, RecursosHumanos, IT, Marketing, Operacoes**:
    correspondem um a um aos seis departamentos da Nortada Logística
    definidos em `01-arquitetura.md`.

- **OU=Contas-Administrativas**: contém todas as contas `adm.primeiro.ultimo`,
  separadas das contas normais dos mesmos utilizadores. Esta separação é o
  princípio de **PAM (Privileged Access Management)** aplicado ao nível
  mais básico: um utilizador com necessidade de privilégios elevados (por
  exemplo, um técnico de IT) usa `ana.pereira` para o dia a dia (email,
  navegação, aplicações de escritório) e só usa `adm.ana.pereira` quando
  precisa de executar uma tarefa administrativa concreta. Isto reduz a
  superfície de exposição da conta privilegiada: se a conta normal for
  comprometida (por exemplo, por phishing), o atacante não herda
  automaticamente privilégios administrativos.

- **OU=Grupos**: contentor de topo para todos os grupos do domínio, com
  duas sub-OUs:
  - **Seguranca**: grupos de segurança (usados para atribuir permissões e
    associar a GPOs), que são o objeto principal deste documento (secção
    3).
  - **Distribuicao**: grupos de distribuição (listas de email sem função de
    segurança, por exemplo `DL-Todos-Marketing`), mantidos separados dos
    grupos de segurança para que uma auditoria a permissões não tenha de
    filtrar ruído de listas de email sem impacto de acesso.

- **OU=Computadores**: contentor de topo para objetos de computador,
  dividido em:
  - **Servidores**: reservada para member servers futuros (não existem
    nesta fase, ver `01-arquitetura.md`, secção 3, mas a OU fica criada
    para não obrigar a reestruturar a árvore mais tarde).
  - **Estacoes**: reservada para estações de trabalho que venham a
    ingressar no domínio.

- **OU=Contas-Servico**: contas de serviço (service accounts) usadas por
  aplicações ou tarefas agendadas, nunca por pessoas. Mantidas separadas
  das contas de utilizador para que políticas de expiração de password ou
  de bloqueio por inatividade, pensadas para pessoas, não se apliquem
  incorretamente a contas de serviço.

- **OU=Contas-Desativadas**: destino final das contas de utilizadores que
  saem da empresa, depois de desativadas pelo processo de offboarding (ver
  `05-onboarding-offboarding.md`). Mantê-las fora das OUs de departamento
  ativo evita que apareçam em listagens ou GPOs pensadas para colaboradores
  ativos, sem as eliminar.

### 2.2. Idempotência do script `01-New-OuStructure.ps1`

O script é desenhado para poder ser executado mais do que uma vez sobre o
mesmo domínio sem duplicar nem falhar de forma destrutiva. Isto é
conseguido através de:

- Antes de criar cada OU, o script verifica a sua existência com
  `Get-ADOrganizationalUnit -Filter` (pesquisa pelo `Name` dentro do
  `SearchBase` correspondente ao pai). Só invoca `New-ADOrganizationalUnit`
  quando a OU não é encontrada.
- A árvore é criada de cima para baixo (primeiro `OU=NORTADA`, depois
  `Utilizadores`, só depois as sub-OUs de departamento), porque cada nível
  depende do `DistinguishedName` do nível anterior já existir como
  `SearchBase` da próxima verificação.
- Uma segunda execução do script, sobre um domínio onde a estrutura já
  existe, não cria objetos novos, não gera erros por objeto duplicado, e
  termina com um resumo do tipo "0 OUs criadas, 14 já existentes" (o número
  exato de OUs a validar quando o script for escrito e corrido).

Esta idempotência é relevante porque o script pode ter de ser corrido
novamente depois de correções a outros scripts (por exemplo, depois de
ajustar `02-New-SecurityGroups.ps1`), sem risco de deixar a árvore de OUs
num estado inconsistente ou de gerar erros que interrompam a execução dos
scripts seguintes.

## 3. Modelo de grupos de segurança (AGDLP)

O script `02-New-SecurityGroups.ps1` cria os grupos de segurança do domínio
seguindo o modelo **AGDLP** (Account, Global, Domain Local, Permission),
prática recomendada da Microsoft para ambientes com uma única floresta e um
único domínio como este:

1. **Account**: as contas de utilizador (`primeiro.ultimo` e
   `adm.primeiro.ultimo`) são colocadas nas OUs de departamento
   correspondentes.
2. **Global**: as contas são adicionadas a **grupos globais**, um por
   departamento ou função (por exemplo, `GG-Financeira`, `GG-RH`,
   `GG-IT-Suporte`, `GG-Direcao`). Um grupo global agrupa contas com a
   mesma função organizacional dentro do domínio.
3. **Domain Local**: os grupos globais são, por sua vez, adicionados a
   **grupos de domínio local** que representam um recurso ou uma permissão
   concreta. O script `02-New-SecurityGroups.ps1` cria, para cada
   departamento, um único grupo de domínio local de leitura (por exemplo,
   `DL-Partilha-Financeira-Leitura`, `DL-Partilha-RH-Leitura`); outras
   variantes de grupo de domínio local (por exemplo, um `DL-...-Escrita` ou
   um grupo associado a uma GPO) não são criadas por este script e ficam
   para uma extensão futura, fora do âmbito da primeira versão do
   laboratório.
4. **Permission**: as permissões sobre o recurso (partilha de ficheiros,
   objeto do AD, GPO) são atribuídas **apenas ao grupo de domínio local**,
   nunca diretamente a um grupo global e nunca diretamente a uma conta de
   utilizador.

Cadeia completa para um exemplo concreto (acesso de leitura à partilha
financeira):

```
adm.ana.pereira / ana.pereira  (Account)
        |
        v
   GG-Financeira                (Global)
        |
        v
DL-Partilha-Financeira-Leitura  (Domain Local)
        |
        v
Permissao NTFS "Leitura" na partilha \\NORTADA-DC01\Financeira  (Permission)
```

### 3.1. Justificação: grupos versus permissões diretas em utilizadores

O modelo AGDLP é escolhido em vez de atribuir permissões diretamente a
cada utilizador, pelos seguintes motivos:

- **Manutenção centralizada.** Quando um colaborador muda de departamento
  ou de função, a alteração de acesso resume-se a retirá-lo de um grupo
  global e colocá-lo noutro. Sem grupos, seria necessário localizar e
  revogar manualmente cada permissão direta espalhada por recursos
  distintos, um processo sujeito a esquecimentos.
- **Auditoria e deteção de desvios.** Uma lista de membros de
  `DL-Partilha-Financeira-Leitura` responde diretamente à pergunta "quem
  tem acesso a este recurso". Com permissões diretas em utilizadores, essa
  pergunta obriga a inspecionar o ACL de cada recurso um a um. Este ponto
  liga diretamente ao modelo de RBAC descrito em `06-rbac.md`: a deteção de
  desvios de privilégios compara os grupos que um utilizador tem com os
  grupos que devia ter segundo o seu cargo, o que só é viável de forma
  automatizável quando o acesso passa exclusivamente por grupos.
- **Redução do número de entradas de controlo de acesso (ACEs).** Um
  recurso com permissões diretas para 20 utilizadores tem 20 ACEs a
  processar em cada verificação de acesso e 20 entradas a rever numa
  auditoria. Com AGDLP, o mesmo recurso tem uma única ACE, atribuída ao
  grupo de domínio local.
- **Separação entre "quem" e "o quê".** O grupo global representa quem a
  pessoa é na organização (função, departamento). O grupo de domínio local
  representa o que pode ser acedido. Separar estas duas dimensões permite
  reutilizar o mesmo grupo global (`GG-Financeira`) em vários grupos de
  domínio local diferentes (leitura numa partilha, escrita noutra, acesso a
  uma impressora departamental) sem repetir a lista de membros em cada um.
- **Coerência com o princípio do menor privilégio e com PAM.** Contas
  administrativas (`adm.primeiro.ultimo`) nunca herdam pertença aos
  mesmos grupos globais de departamento que as contas normais equivalentes:
  têm os seus próprios grupos (detalhados em `06-rbac.md`), o que evita que
  uma permissão pensada para uma conta administrativa seja concedida
  inadvertidamente à conta do dia a dia da mesma pessoa.

### 3.2. Localização no AD

- Os grupos globais e os grupos de domínio local ficam ambos em
  `OU=Seguranca` sob `OU=Grupos`, distinguíveis pelo prefixo do nome
  (`GG-` para grupo global, `DL-` para grupo de domínio local) em vez de
  por OUs separadas, para manter a árvore de OUs simples.
- Os grupos de distribuição (email) ficam em `OU=Distribuicao`, com
  prefixo `DG-` (por exemplo, `DG-Todos-Marketing`), e não participam no
  modelo AGDLP porque não concedem permissões.
- O script `02-New-SecurityGroups.ps1` cria exatamente os seguintes
  grupos: os grupos globais `GG-Direcao`, `GG-Financeira`, `GG-RH`,
  `GG-IT-Suporte`, `GG-Marketing`, `GG-Operacoes` (um por departamento) e
  `GG-IT-Admins` (grupo administrativo, PAM); e um grupo de domínio local
  de leitura por departamento, `DL-Partilha-<Departamento>-Leitura`
  (`DL-Partilha-Direcao-Leitura`, `DL-Partilha-Financeira-Leitura`,
  `DL-Partilha-RH-Leitura`, `DL-Partilha-IT-Leitura`,
  `DL-Partilha-Marketing-Leitura`, `DL-Partilha-Operacoes-Leitura`). Para
  cada departamento, o script adiciona automaticamente o `GG-` correspondente
  como membro do `DL-` correspondente; `GG-IT-Admins` não tem um grupo de
  domínio local associado criado por este script. Os parâmetros do script
  são `-DomainDN` (por omissão `DC=nortada,DC=local`) e `-GruposOuPath`
  (por omissão `OU=Seguranca,OU=Grupos,OU=NORTADA`, um caminho relativo ao
  `DomainDN`).

## 4. Fora de âmbito deste documento

A lista concreta e completa de grupos por cargo, os grupos críticos do
domínio (Domain Admins e afins) e a matriz de permissões e proibições por
função ficam detalhados em `06-rbac.md`. Este documento cobre apenas a
estrutura de OUs e o mecanismo AGDLP em si.

Este documento foi afinado depois de os scripts `01-New-OuStructure.ps1` e
`02-New-SecurityGroups.ps1` estarem finalizados, para que os exemplos e os
nomes de parâmetros aqui descritos correspondam exatamente à implementação
real.
