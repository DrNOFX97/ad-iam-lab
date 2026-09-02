# ad-iam-lab

Laboratório de Active Directory e gestão de identidades (IAM) da empresa
fictícia Nortada Logística, Lda., construído como projeto de portefólio no
âmbito de um CET de Cibersegurança (Faro, Portugal).

O projeto serve dois objetivos:

1. Demonstrar, de forma concreta e documentada, competências de gestão de
   identidades: estrutura de Unidades Organizacionais (OUs), modelo de
   grupos AGDLP, RBAC por departamento, processos de onboarding e
   offboarding, e separação de contas administrativas segundo o princípio
   PAM (Privileged Access Management).
2. Gerar eventos Windows reais (logons, autenticação, criação de
   utilizadores, alterações a grupos, elevação de privilégios) que
   alimentam o SentryLens, um dashboard de SOC já existente e funcional
   noutro repositório, através de um agente Wazuh instalado no
   controlador de domínio deste laboratório.

Este repositório é deliberadamente separado do SentryLens: um é gestão de
identidades e governação, o outro é deteção e apresentação de eventos. Ver
secção "Relação com o SentryLens" mais abaixo.

## A empresa fictícia: Nortada Logística, Lda.

Todo o laboratório é modelado à volta de uma empresa de logística
fictícia, com os seguintes dados:

- Domínio Active Directory: `nortada.local`
- Nome NetBIOS: `NORTADA`
- Departamentos: Direção, Financeira, Recursos Humanos, IT, Marketing,
  Operações.
- Convenção de contas:
  - Contas normais: `primeiro.ultimo` (por exemplo, `ana.pereira`).
  - Contas administrativas: `adm.primeiro.ultimo` (por exemplo,
    `adm.ana.pereira`), separadas da conta normal do mesmo utilizador
    segundo o princípio PAM.

## Arquitetura (resumo)

```
+----------------------+
| NORTADA-DC01         |
| Windows Server 2022  |
| 192.168.1.150        |
| Agente Wazuh         |
+----------+-----------+
           | portas 1514 (dados) / 1515 (registo do agente)
           v
+----------------------+
| Wazuh Manager         |
| 192.168.1.143         |  --- API de gestao: porta 55000
+----------+-----------+
           | indexacao interna
           v
+----------------------+
| Wazuh Indexer         |
| (OpenSearch)          |
| porta 9200             |
| (mesma VM, .143)      |
+----------+-----------+
           | consultas HTTP (API 55000 / Indexer 9200)
           v
+----------------------+
| Backend SentryLens    |
| Windows anfitriao     |
| porta 8001             |
+----------+-----------+
           | HTTP (fetch do frontend)
           v
+----------------------+
| Dashboard SentryLens  |
| index.html (estatico) |
+----------------------+
```

O Wazuh Manager, o Wazuh Indexer e o backend do SentryLens já existem e
estão operacionais noutro repositório (SentryLens): este laboratório
apenas acrescenta o `NORTADA-DC01` e o respetivo agente Wazuh a essa
topologia já existente. Para o detalhe completo (justificação da rede,
endereçamento IP, tabela de portas, caminho ponta a ponta do evento), ver
[`docs/01-arquitetura.md`](docs/01-arquitetura.md) e
[`docs/07-integracao-wazuh-sentrylens.md`](docs/07-integracao-wazuh-sentrylens.md).

## Pré-requisitos de hardware

O laboratório corre na mesma torre física já usada para o laboratório
SentryLens:

- CPU: Intel i5-14400F (10 núcleos / 16 threads).
- RAM: 32 GB.
- Armazenamento: SSD NVMe.

Com estes recursos, correr em simultâneo a VM Wazuh existente e a nova VM
`NORTADA-DC01` (Windows Server 2022 Evaluation, 4 GB RAM, 2 vCPU, 60 GB de
disco dinâmico, controlador gráfico VMSVGA), mais o backend do SentryLens
e o browser do dashboard, é confortável e não deve gerar pressão de
memória. Detalhe do dimensionamento em
[`docs/01-arquitetura.md`](docs/01-arquitetura.md), secção 6.

## Ordem de execução (prevista)

Nesta entrega existe apenas a documentação de arquitetura e processos
(`docs/`). Os scripts PowerShell referidos abaixo ainda não existem neste
repositório: ficam para um passo/prompt seguinte. A ordem prevista, tal
como documentada em `docs/02` a `docs/05`, é:

1. Criar a VM `NORTADA-DC01` no VirtualBox com as especificações definidas
   em `docs/01-arquitetura.md` (Windows Server 2022 Evaluation, 4 GB RAM,
   2 vCPU, 60 GB de disco dinâmico, VMSVGA, adaptador em modo Bridged).
2. Instalação manual e interativa do Windows Server 2022 Evaluation nessa
   VM (não automatizada, tal como a instalação do Ubuntu Server no
   laboratório Wazuh).
3. `00-Install-DomainController.ps1`: configura rede estática
   (192.168.1.150), instala as roles AD DS e DNS, e promove a máquina a
   Controlador de Domínio da floresta `nortada.local`, com reinício
   automático incluído no final da promoção.
4. `01-New-OuStructure.ps1`: cria a árvore de OUs sob `OU=NORTADA`.
5. `02-New-SecurityGroups.ps1`: cria os grupos de segurança segundo o
   modelo AGDLP.
6. `05-Set-AuditPolicy.ps1`: ativa a Advanced Audit Policy e aumenta o
   log de Segurança para 512 MB, antes de instalar o agente Wazuh, para
   que os eventos gerados desde o primeiro momento fiquem registados.
7. Instalação do agente Wazuh no DC (mesmo procedimento já usado no
   laboratório SentryLens, apontado ao IP 192.168.1.150 deste DC e ao
   Manager em 192.168.1.143).
8. `03-Onboard-Users.ps1`: cria contas a partir de `data/colaboradores.csv`,
   conforme necessário.
9. `04-Offboard-User.ps1`: desativa contas a partir de `data/saidas.csv`,
   conforme necessário.

## Estrutura do repositório

```
ad-iam-lab/
  README.md
  .gitignore
  docs/
    01-arquitetura.md
    02-instalacao-dc.md
    03-estrutura-ou-grupos.md
    04-politica-auditoria.md
    05-onboarding-offboarding.md
    06-rbac.md
    07-integracao-wazuh-sentrylens.md
  scripts/          (vazia por agora, apenas .gitkeep)
  data/             (vazia por agora, apenas .gitkeep)
  wazuh/
    local_rules.xml
    ossec-agent-windows.conf
  evidencias/       (vazia por agora, apenas .gitkeep)
```

## Porquê cada decisão

Esta é a secção mais importante do repositório para efeitos de entrevista
de emprego: resume as decisões de desenho já tomadas e porquê, com
referência ao documento onde cada uma está justificada em detalhe.

- **VirtualBox e rede partilhada (Bridged Adapter) com o Wazuh Manager
  existente, em vez de rede interna isolada.** O Wazuh Manager já está
  operacional em 192.168.1.143 e não tem uma segunda interface para servir
  de ponte a uma rede interna dedicada; ligar o DC à mesma sub-rede
  192.168.1.0/24 evita NAT e routing adicional, reduzindo pontos de falha
  entre o agente e o Manager. Ver
  [`docs/01-arquitetura.md`](docs/01-arquitetura.md), secção 3.

- **Um único Controlador de Domínio, sem member servers nesta fase.** Um
  único DC (`NORTADA-DC01`) é suficiente para demonstrar gestão de
  identidades, RBAC, GPOs e geração de eventos de segurança relevantes,
  sem a complexidade adicional de replicação ou de servidores membro que
  não acrescentam valor de portefólio nesta fase. Ver
  [`docs/01-arquitetura.md`](docs/01-arquitetura.md), secção 3.

- **Estrutura de OUs sob uma OU de topo única (`OU=NORTADA`).** Isola
  todos os objetos geridos pelo laboratório dos contentores nativos do AD
  (`Users`, `Computers`), facilita a aplicação de GPOs a um único ponto da
  árvore e simplifica uma eventual exportação ou remoção completa da
  estrutura. Ver [`docs/03-estrutura-ou-grupos.md`](docs/03-estrutura-ou-grupos.md),
  secção 2.

- **Modelo AGDLP em vez de permissões diretas em utilizadores.** Atribuir
  permissões apenas a grupos de domínio local (alimentados por grupos
  globais, por sua vez alimentados por contas) centraliza a manutenção de
  acessos, torna a auditoria de "quem tem acesso a quê" direta, e é a base
  técnica que permite a deteção automatizável de desvios de privilégios.
  Ver [`docs/03-estrutura-ou-grupos.md`](docs/03-estrutura-ou-grupos.md),
  secção 3.1.

- **Separação de contas administrativas por PAM.** Cada colaborador com
  necessidade de privilégios elevados tem duas contas distintas
  (`primeiro.ultimo` para o dia a dia, `adm.primeiro.ultimo` para tarefas
  administrativas), em OUs e grupos globais diferentes, para que o
  compromisso da conta normal não implique automaticamente privilégios
  administrativos. Ver
  [`docs/03-estrutura-ou-grupos.md`](docs/03-estrutura-ou-grupos.md),
  secção 2.1, e [`docs/06-rbac.md`](docs/06-rbac.md), secção 2.1 (campo
  `conta_associada`).

- **Contas nunca são eliminadas no offboarding.** O processo desativa,
  revoga sessões e password, remove de grupos e move para
  `OU=Contas-Desativadas`, mas nunca chama `Remove-ADObject`: preserva o
  SID para investigação forense e para não deixar propriedade de
  ficheiros órfã, e mantém a reversão de um erro de processo simples
  (reativar) em vez de irreversível (eliminar). Ver
  [`docs/05-onboarding-offboarding.md`](docs/05-onboarding-offboarding.md),
  secção 3.3.

- **Aumento do log de Segurança para 512 MB.** Com as subcategorias de
  auditoria mais verbosas ativas (Logon, Process Creation), o log de
  Segurança por omissão do Windows Server 2022 satura depressa e começa a
  sobrescrever eventos antes de o agente Wazuh os ler, resultando em perda
  silenciosa de eventos; 512 MB dá margem suficiente para um DC de
  laboratório com baixo volume. Ver
  [`docs/04-politica-auditoria.md`](docs/04-politica-auditoria.md),
  secção 4.

- **Baseline de RBAC como ficheiro de referência único
  (`data/rbac_baseline.json`).** Um único ficheiro que mapeia cargo a
  grupos permitidos, grupos proibidos e nível de risco serve de fonte
  única de verdade tanto para o onboarding (que grupos atribuir) como para
  uma futura deteção de desvios de privilégios no SentryLens, evitando
  duas listas divergentes mantidas em separado. Ver
  [`docs/06-rbac.md`](docs/06-rbac.md), secções 1 e 2.

- **Regras Wazuh locais apenas para os Event IDs 4723 e 4724, em nível
  baixo (nível 3) em vez de um nível de alerta alto.** A investigação
  direta ao ruleset base oficial do Wazuh (branch 4.14.9) confirmou que 17
  dos 19 Event IDs de auditoria de AD relevantes para este laboratório já
  têm regra própria no ruleset base; escrever regra local para os 19 seria
  trabalho redundante e risco de duplicar alertas que o Wazuh já gera
  sozinho. Dos dois Event IDs sem regra base, `4723` (tentativa de
  alteração de password pelo próprio utilizador) e `4724` (reset de
  password de outra conta por um administrador) são eventos
  administrativos esperados do próprio funcionamento do laboratório, não
  uma deteção de ataque, pelo que o nível escolhido é baixo (nível 3) e
  não um nível de alerta alto; mesmo assim, nível igual ou superior a 3 é
  o mínimo para o Wazuh gerar alerta e indexar o evento, condição
  necessária para os futuros painéis do SentryLens conseguirem
  consultá-lo. Ver `wazuh/local_rules.xml` (comentário de topo) e
  [`docs/07-integracao-wazuh-sentrylens.md`](docs/07-integracao-wazuh-sentrylens.md),
  secções 3 e 5.

## Relação com o SentryLens

O `ad-iam-lab` e o SentryLens são repositórios distintos e propositadamente
separados: este repositório trata de gestão de identidades e governação
(AD, OUs, RBAC, onboarding/offboarding, PAM); o SentryLens
(`C:\Users\fnuno\OneDrive\Projetos\SentryLens`) é o dashboard de SOC que
consome eventos Wazuh e já está operacional de forma independente deste
laboratório.

Os dois projetos ligam-se por dois pontos concretos:

1. O agente Wazuh instalado no `NORTADA-DC01` envia eventos reais gerados
   por este laboratório (logons, criação de contas, alterações de grupo)
   para o mesmo Wazuh Manager (192.168.1.143) que o SentryLens já consulta,
   passando a existir dados reais de IAM no dashboard.
2. Referência cruzada explícita entre os READMEs e a documentação de
   ambos os repositórios, para que quem consulte um projeto encontre
   facilmente o outro.

## Estado atual do projeto

**Já existe:**

- Documentação completa da arquitetura de rede, endereçamento IP e caminho
  do evento até ao dashboard (`docs/01-arquitetura.md`,
  `docs/07-integracao-wazuh-sentrylens.md`).
- Documentação completa do processo de instalação e promoção do
  Controlador de Domínio (`docs/02-instalacao-dc.md`).
- Documentação completa da estrutura de OUs e do modelo de grupos AGDLP
  (`docs/03-estrutura-ou-grupos.md`).
- Documentação completa da política de auditoria avançada a aplicar
  (`docs/04-politica-auditoria.md`).
- Documentação completa dos processos de onboarding e offboarding
  (`docs/05-onboarding-offboarding.md`).
- Documentação completa do modelo de RBAC e da deteção de desvios de
  privilégios prevista (`docs/06-rbac.md`).
- Diagnóstico documentado da limitação conhecida do ruleset base do Wazuh
  para vários Event IDs de gestão de contas e grupos do AD
  (`docs/07-integracao-wazuh-sentrylens.md`, secção 3).

**Falta (pendente para passos seguintes):**

- Os scripts PowerShell propriamente ditos:
  `00-Install-DomainController.ps1`, `01-New-OuStructure.ps1`,
  `02-New-SecurityGroups.ps1`, `03-Onboard-Users.ps1`,
  `04-Offboard-User.ps1`, `05-Set-AuditPolicy.ps1`.
- Os ficheiros de dados: `data/colaboradores.csv`, `data/saidas.csv`,
  `data/rbac_baseline.json`.
- As regras Wazuh personalizadas (`wazuh/local_rules.xml`) e o excerto de
  configuração do agente Windows (`wazuh/ossec-agent-windows.conf`).
- A criação real da VM `NORTADA-DC01` e a instalação do Windows Server
  2022 Evaluation.
- Qualquer validação prática: nada neste repositório foi ainda executado
  contra uma VM real. Não há confirmação de que a promoção do DC funciona,
  de que a política de auditoria gera os Event IDs esperados, de que o
  agente Wazuh regista eventos, nem de que esses eventos chegam
  efetivamente ao dashboard do SentryLens. Todos os passos descritos nos
  documentos são desenho, não resultado observado.
