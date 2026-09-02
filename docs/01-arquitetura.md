# Arquitetura do laboratório AD + Wazuh

## 1. Contexto e objetivo

Este documento descreve a arquitetura do laboratório de Active Directory da
empresa fictícia **Nortada Logística, Lda.** (domínio `nortada.local`,
NetBIOS `NORTADA`), construído para dois fins:

1. Servir de projeto de portefólio de gestão de identidades (utilizadores,
   grupos, OUs, RBAC por departamento, GPOs, processos de onboarding e
   offboarding, contas administrativas separadas segundo o princípio PAM).
2. Gerar eventos Windows reais (logon, autenticação Kerberos, alterações a
   objetos do AD, elevação de privilégios) que alimentam o **SentryLens**,
   o dashboard de SOC já existente e funcional noutro repositório.

Departamentos da Nortada Logística: Direção, Financeira, Recursos Humanos,
IT, Marketing, Operações. Convenção de contas: `primeiro.ultimo` para
contas normais, `adm.primeiro.ultimo` para contas administrativas.

Este documento cobre apenas o desenho da arquitetura. A implementação
(scripts de instalação e configuração) é tratada num passo posterior, ver
secção 6.

## 2. Estado atual do SentryLens (ponto de partida)

O laboratório do SentryLens já está operacional e não é alterado por este
projeto:

- Hipervisor: VirtualBox (não Hyper-V; a documentação antiga do SentryLens
  referia Hyper-V, mas na prática o laboratório corre em VirtualBox).
- Uma VM Ubuntu Server com a stack Wazuh completa:
  - `wazuh-manager` com a API de gestão na porta 55000, e as portas de
    receção de eventos de agentes 1514 (dados) e 1515 (registo de agentes).
  - `wazuh-indexer` (OpenSearch) na porta 9200.
  - `wazuh-dashboard` na porta 443.
- IP da VM Wazuh: **192.168.1.143**, na rede local de casa do utilizador
  (192.168.1.0/24), uma rede doméstica real, não uma rede interna isolada.
- Backend do SentryLens (FastAPI, `scripts/main.py` no repositório
  SentryLens) a correr no Windows anfitrião, porta **8001**, que consulta a
  API do Wazuh Manager e o Indexer e expõe os dados ao dashboard estático
  (`index.html`).

Esta topologia é a base de rede que o laboratório de AD tem de respeitar
para conseguir enviar eventos para o Wazuh.

## 3. Inventário de VMs do laboratório de AD

Proposta: **uma única VM**.

| VM | Papel | SO | RAM | vCPU | Disco | Controlador gráfico |
|---|---|---|---|---|---|---|
| `NORTADA-DC01` | Controlador de Domínio do domínio `nortada.local` (AD DS, DNS integrado, futuramente GPOs) | Windows Server 2022 Evaluation | 4 GB | 2 | 60 GB (dinâmico) | VMSVGA |

Não são propostas VMs adicionais nesta fase (sem member servers, sem
estações cliente dedicadas): um único DC é suficiente para demonstrar
gestão de identidades, RBAC via grupos e OUs, GPOs, e para gerar eventos de
segurança do AD (4624, 4625, 4720, 4726, 4738, 4732, etc.) que interessam
ao SentryLens. O agente Wazuh é instalado diretamente neste DC.

### Rede: mesma rede do Wazuh Manager (decisão) e justificação

Foram consideradas duas opções:

**Opção A. Rede interna VirtualBox dedicada** (isolada do resto da rede de
casa), com NAT ou routing manual para alcançar o Manager.

**Opção B. Mesma rede local de casa (192.168.1.0/24)**, em modo *Bridged
Adapter* no VirtualBox, tal como (presumivelmente) está configurada a VM do
Wazuh Manager para ser alcançável a partir do backend no Windows anfitrião.

**Decisão: Opção B.**

Justificação:

- O Wazuh Manager já existe, já está operacional em 192.168.1.143, e não
  vai ser modificado nem tem uma segunda interface de rede para servir de
  ponte para uma rede interna isolada. Criar uma rede interna dedicada
  obrigaria a configurar routing ou NAT adicional no anfitrião apenas para
  o DC alcançar o Manager, o que acrescenta complexidade sem benefício de
  segurança relevante neste contexto de laboratório doméstico de
  portefólio.
- O objetivo principal do DC é gerar eventos para o SentryLens. Ligação
  direta e simples (mesma sub-rede, sem NAT nem hairpin routing) reduz
  pontos de falha entre o agente Wazuh e o Manager (portas 1514/1515) e
  entre eventuais testes manuais e a API (porta 55000).
- O isolamento de um DC de produção justificaria normalmente uma rede
  segregada (o AD é um ativo crítico). Neste caso trata-se de um
  laboratório isolado do resto do mundo pela própria rede doméstica NAT do
  router (não exposto à Internet), pelo que o risco adicional de partilhar
  a sub-rede 192.168.1.0/24 com a VM Wazuh é aceitável face ao ganho de
  simplicidade.
- Fica documentado como limitação conhecida: num cenário real, o DC estaria
  numa VLAN de gestão segregada, com o Wazuh Manager e o backend acessíveis
  apenas através de regras de firewall explícitas nas portas necessárias
  (1514, 1515, 55000, 9200, 8001), não em rede plana partilhada.

Configuração de rede da VM no VirtualBox: adaptador de rede em modo
**Bridged Adapter**, associado ao adaptador físico do anfitrião ligado à
rede de casa, para que o DC receba um IP na mesma sub-rede 192.168.1.0/24
e seja diretamente alcançável pela VM Wazuh e vice-versa.

## 4. Endereçamento IP

| Host | IP | Papel |
|---|---|---|
| Router de casa | 192.168.1.1 (assumido, típico) | Gateway / DHCP |
| VM Wazuh (SentryLens, existente) | 192.168.1.143 | Manager + Indexer + Dashboard |
| Windows anfitrião (torre, SentryLens) | IP na mesma sub-rede, DHCP | Backend SentryLens na porta 8001 |
| **VM `NORTADA-DC01` (nova, este laboratório)** | **192.168.1.150** | Controlador de Domínio |

Notas:

- 192.168.1.150 é escolhido por estar fora do intervalo tipicamente
  reservado pelo DHCP de routers domésticos comuns (que normalmente
  distribuem a partir de .100 até .149 ou .199) e por não colidir com
  192.168.1.143. Antes da instalação real, confirmar no router doméstico
  do utilizador que este IP não está a ser atribuído por DHCP a outro
  dispositivo, e reservá-lo (IP estático na VM, fora do pool DHCP, ou
  reserva DHCP por MAC address no router).
- O DC deve ter IP estático (não DHCP), como é prática recomendada para
  qualquer controlador de domínio, dado que aloja também o serviço DNS do
  domínio.
- DNS do DC: aponta para si próprio (127.0.0.1 ou 192.168.1.150) como
  servidor DNS primário, uma vez que o DNS integrado no AD é instalado
  juntamente com o AD DS.
- Máscara de sub-rede: 255.255.255.0 (/24), igual à rede de casa existente.
- Gateway: o IP do router de casa (assumir 192.168.1.1, a confirmar no
  ambiente real do utilizador antes da instalação).

## 5. Caminho do tráfego até ao Wazuh e ao dashboard

Sequência completa, desde o evento gerado no DC até ser visível no
dashboard do SentryLens:

1. Um evento de segurança ocorre no `NORTADA-DC01` (ex.: logon falhado,
   criação de utilizador, alteração de grupo) e fica registado no Windows
   Event Log.
2. O agente Wazuh instalado no DC lê esse evento e envia-o, cifrado, para
   o Wazuh Manager (192.168.1.143) nas portas 1514 (transmissão de dados
   de eventos) e 1515 (usada no registo/enrolment do agente).
3. O Wazuh Manager processa o evento contra as suas regras de deteção e
   indexa o resultado no Wazuh Indexer / OpenSearch, na porta 9200.
4. O backend do SentryLens, a correr no Windows anfitrião na porta 8001,
   consulta periodicamente a API do Wazuh Manager (porta 55000) e/ou o
   Indexer (porta 9200) para obter os dados processados.
5. O dashboard estático do SentryLens (`index.html`) consome o backend na
   porta 8001 e apresenta os eventos ao utilizador.

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
| VM Wazuh (existente) |
| 192.168.1.143        |
| wazuh-manager        |  --- API de gestao: porta 55000
+----------+-----------+
           | indexacao interna
           v
+----------------------+
| wazuh-indexer         |
| (OpenSearch)          |
| porta 9200            |
| (mesma VM, .143)      |
+----------+-----------+
           | consultas HTTP (API 55000 / Indexer 9200)
           v
+----------------------+
| Backend SentryLens    |
| Windows anfitriao     |
| porta 8001            |
+----------+-----------+
           | HTTP (fetch do frontend)
           v
+----------------------+
| Dashboard SentryLens  |
| index.html (estatico) |
+----------------------+
```

Portas envolvidas, resumo:

| Origem | Destino | Porta | Finalidade |
|---|---|---|---|
| Agente Wazuh (DC01, .150) | Wazuh Manager (.143) | 1514/TCP | Envio de eventos |
| Agente Wazuh (DC01, .150) | Wazuh Manager (.143) | 1515/TCP | Registo do agente |
| Ferramentas de administração / backend | Wazuh Manager (.143) | 55000/TCP | API de gestão do Wazuh |
| Wazuh Manager (.143) | Wazuh Indexer (.143) | 9200/TCP | Indexação (interno à VM) |
| Backend SentryLens (anfitrião) | Wazuh Indexer/API (.143) | 9200 / 55000 | Consulta de dados |
| Dashboard (`index.html`) | Backend SentryLens (anfitrião) | 8001/TCP | Consumo de dados pelo frontend |

## 6. Requisitos de hardware do anfitrião

Anfitrião: torre existente, já usada para o laboratório SentryLens.

- CPU: Intel i5-14400F (10 núcleos / 16 threads).
- RAM: 32 GB.
- Armazenamento: SSD NVMe.

Consumo estimado com a VM adicional deste laboratório:

| Recurso | Já em uso (VM Wazuh) | Adicional (NORTADA-DC01) | Total aproximado |
|---|---|---|---|
| RAM | tipicamente 4 a 8 GB atribuídos à VM Wazuh | 4 GB | 8 a 12 GB de 32 GB disponíveis |
| vCPU | 2 a 4 vCPU atribuídos | 2 vCPU | dentro da folga do i5-14400F |
| Disco | conforme dimensionado no laboratório Wazuh | até 60 GB (disco dinâmico, ocupação real inicial muito menor) | folga confortável num SSD NVMe de dimensão habitual (500 GB+) |

Com 32 GB de RAM no anfitrião, correr as duas VMs (Wazuh + DC) em
simultâneo, mais o backend do SentryLens e o browser para o dashboard,
é confortável e não deve gerar pressão de memória, mesmo contando com a
sobrecarga normal do Windows anfitrião e do VirtualBox. Não são
necessários upgrades de hardware para este laboratório.

## 7. Fora de âmbito deste documento

Este documento descreve apenas o desenho da arquitetura (VMs, rede,
endereçamento, caminho do tráfego até ao Wazuh). A implementação prática,
isto é, os scripts que efetivamente criam e configuram a VM, promovem o
Controlador de Domínio, criam OUs, utilizadores, grupos e GPOs, e instalam
o agente Wazuh (a começar por um script `00-Install-DomainController.ps1`
e seguintes), será produzida num passo posterior e não faz parte desta
entrega. Qualquer IP, nome de VM ou porta aqui definido é a base a seguir
nesses scripts, para manter a coerência entre o desenho e a implementação.

Validação prática desta arquitetura (ligação real do agente ao Manager,
chegada de eventos ao Indexer, visibilidade no dashboard) está pendente de
validação, a realizar apenas depois de a VM e os scripts de instalação
existirem.
