# Instalação e promoção do Controlador de Domínio

## 1. Objetivo

Este documento descreve o passo a passo de instalação do Windows Server na
VM `NORTADA-DC01` e da promoção a Controlador de Domínio da floresta
`nortada.local`, conforme desenhado em `01-arquitetura.md`. A execução
prática deste passo a passo é automatizada, num passo posterior fora do
âmbito deste documento, pelo script `00-Install-DomainController.ps1`.

Este documento não contém o código do script, apenas o que ele vai fazer,
por que ordem, e porquê.

## 2. Pré-requisitos antes de correr o script

Antes de sequer criar ou arrancar a VM `NORTADA-DC01`:

1. Confirmar no router de casa que o IP **192.168.1.150** não está a ser
   atribuído por DHCP a nenhum outro dispositivo (ver `01-arquitetura.md`,
   secção 4). Se necessário, excluir esse IP do pool de DHCP do router ou
   reservá-lo por MAC address.
2. Confirmar que a VM Wazuh (192.168.1.143) está acessível a partir da rede
   de casa (`ping 192.168.1.143` a partir do anfitrião Windows).
3. Ter o ISO do Windows Server 2022 Evaluation disponível (download da
   Microsoft Evaluation Center) para a instalação inicial do sistema
   operativo na VM.
4. Criar a VM `NORTADA-DC01` no VirtualBox com as especificações definidas
   na arquitetura: Windows Server 2022 Evaluation, 4 GB RAM, 2 vCPU, 60 GB
   de disco dinâmico, controlador gráfico VMSVGA, adaptador de rede em modo
   Bridged Adapter associado ao adaptador físico do anfitrião ligado à rede
   de casa.
5. Instalar o Windows Server 2022 (Desktop Experience ou Server Core,
   conforme preferência; este laboratório assume Desktop Experience para
   facilitar a gestão local através de ferramentas gráficas como o AD Users
   and Computers) e aplicar as atualizações do Windows Update disponíveis.

Este passo de instalação do sistema operativo é manual e interativo (como a
instalação do Ubuntu Server no laboratório Wazuh), não é automatizado por
nenhum script.

## 3. O que o script `00-Install-DomainController.ps1` vai fazer

O script corre dentro da VM `NORTADA-DC01`, já com o Windows Server
instalado, através de uma sessão PowerShell com privilégios de
Administrador local. Passos previstos, por ordem:

### 3.1. Verificações prévias

- Confirmar que está a correr com privilégios elevados (Administrador).
- Confirmar que a máquina ainda não é um Controlador de Domínio (evitar
  correr a promoção duas vezes sobre a mesma máquina).
- Confirmar que o adaptador de rede ativo corresponde ao esperado, antes de
  lhe atribuir um IP estático.

### 3.2. Configuração de rede

- Atribuir o IP estático **192.168.1.150/24** ao adaptador de rede da VM.
- Definir a gateway como **192.168.1.1** (o router de casa, a confirmar no
  ambiente real do utilizador).
- Definir o servidor DNS primário como **127.0.0.1** (a própria máquina),
  já que o serviço DNS vai ser instalado localmente como parte do AD DS.

Isto é feito antes da instalação das roles, porque um Controlador de
Domínio com IP dinâmico é uma prática desaconselhada: o AD e o DNS
integrado dependem de um endereço estável para que os restantes membros do
domínio (e futuramente o agente Wazuh) o consigam localizar de forma
consistente.

### 3.3. Instalação das roles AD DS e DNS

- Instalar a role **AD-Domain-Services** (Active Directory Domain
  Services).
- Instalar a role **DNS** (DNS Server), que ficará integrada com o AD.
- Instalar as ferramentas de gestão associadas (RSAT correspondentes), para
  permitir gerir o domínio a partir da própria consola do DC.

### 3.4. Criação da floresta `nortada.local`

- Promover a máquina a Controlador de Domínio de uma **nova floresta**
  (`Install-ADDSForest`), com:
  - Nome de domínio: `nortada.local`.
  - Nome NetBIOS: `NORTADA`.
  - Nível funcional da floresta e do domínio: Windows Server 2016 ou
    superior (o mais alto disponível nesta versão do Windows Server, dado
    que não há necessidade de compatibilidade com controladores de domínio
    mais antigos neste laboratório).
  - Instalação do DNS integrado no AD marcada como verdadeira.
  - Diretório de base de dados, ficheiros de log e SYSVOL nos caminhos
    predefinidos (`C:\Windows\NTDS`, `C:\Windows\SYSVOL`), por não haver
    razão neste laboratório para os separar em discos distintos.
- A password do modo de restauro de serviços de diretório (DSRM) é pedida
  de forma segura (como `SecureString`, nunca em texto simples nos
  parâmetros nem gravada em log), dado tratar-se de uma credencial de
  recuperação crítica.
- A máquina reinicia automaticamente no final da promoção, como exigido
  pelo processo `Install-ADDSForest`.

### 3.5. Verificação pós-promoção

Depois do reinício, o script (ou uma segunda execução do mesmo script com
um parâmetro de verificação) confirma:

- Que o serviço **NTDS** (Active Directory Domain Services) está `Running`.
- Que o serviço **DNS Server** está `Running`.
- Que a resolução de nomes local funciona (`Resolve-DnsName nortada.local`
  a partir do próprio DC).
- Que `Get-ADDomain` devolve o domínio `nortada.local` corretamente.

Esta verificação fica registada em consola (e, se aplicável, num ficheiro
de log simples), mas os resultados reais desta verificação só existem
depois de o script correr contra a VM real. Este documento não antecipa
nem inventa esses resultados: ficam pendentes de execução e validação pelo
utilizador.

## 4. Porque a promoção usa parâmetros em vez de valores fixos no script

O script `00-Install-DomainController.ps1` recebe como parâmetros (com
valores predefinidos iguais aos definidos em `01-arquitetura.md`, mas
substituíveis na linha de comandos): o nome de domínio, o nome NetBIOS, o
IP estático, a máscara de sub-rede, a gateway e o nome da interface de
rede.

Motivos para não fixar estes valores diretamente no corpo do script:

1. **Reutilização.** O mesmo script serve de base para outro domínio de
   laboratório ou outro ambiente (por exemplo, se o utilizador decidir
   replicar este laboratório numa rede diferente de 192.168.1.0/24), sem
   precisar de editar a lógica interna, apenas os parâmetros de entrada.
2. **Legibilidade e auditoria.** Correr o script com
   `-DomainName nortada.local -StaticIP 192.168.1.150` deixa explícito, no
   próprio histórico de comandos, que valores foram usados numa execução
   concreta, o que é relevante num laboratório cujo propósito inclui
   demonstrar boas práticas de gestão de infraestrutura.
3. **Prevenção de erros silenciosos.** Com parâmetros validados
   (`ValidatePattern`, `ValidateScript` em PowerShell) é possível rejeitar
   antecipadamente um IP fora do formato esperado ou um nome de domínio
   inválido, antes de a promoção do AD arrancar e deixar a máquina num
   estado intermédio difícil de reverter.
4. **Consistência com os restantes scripts do laboratório.** Os scripts
   seguintes (`01-New-OuStructure.ps1`, `02-New-SecurityGroups.ps1`, etc.)
   seguem o mesmo princípio de parametrização em vez de valores fixos, pelo
   que manter esta convenção desde o primeiro script simplifica a
   manutenção do conjunto todo.

## 5. Fora de âmbito deste documento

Este documento não cobre a criação de OUs, grupos, utilizadores, políticas
de auditoria nem a instalação do agente Wazuh no DC. Esses passos estão
documentados em `03-estrutura-ou-grupos.md`, `04-politica-auditoria.md`,
`05-onboarding-offboarding.md` e `06-rbac.md`, e a instalação do agente
Wazuh segue o mesmo procedimento já usado no laboratório SentryLens
existente, adaptado ao IP 192.168.1.150 deste DC.
