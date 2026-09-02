# Modelo de RBAC e deteção de desvios de privilégios

## 1. Objetivo

Este documento descreve o modelo de Role-Based Access Control (RBAC) do
laboratório: que grupos de segurança cada cargo da Nortada Logística deve
ter, que grupos lhe estão explicitamente vedados, e o nível de risco
associado. Este modelo fica materializado num ficheiro de referência,
**`data/rbac_baseline.json`**, a criar num passo posterior fora do âmbito
deste documento, que serve de fonte única de verdade tanto para os scripts
de onboarding e offboarding (`05-onboarding-offboarding.md`) como para uma
futura funcionalidade de deteção de desvios de privilégios no SentryLens.

## 2. Estrutura do ficheiro `data/rbac_baseline.json`

O ficheiro mapeia cada cargo a três coisas: os grupos que lhe são
permitidos, os grupos que lhe são explicitamente proibidos, e um nível de
risco associado ao cargo. Estrutura prevista:

```json
{
  "cargos": {
    "Diretor Geral": {
      "departamento": "Direcao",
      "grupos_permitidos": ["GG-Direcao", "DL-Partilha-Direcao-Leitura", "DL-Partilha-Direcao-Escrita"],
      "grupos_proibidos": ["Domain Admins", "Enterprise Admins", "Schema Admins"],
      "nivel_risco": "medio"
    },
    "Tecnico de Suporte IT": {
      "departamento": "IT",
      "grupos_permitidos": ["GG-IT-Suporte", "DL-Partilha-IT-Leitura", "DL-Partilha-IT-Escrita"],
      "grupos_proibidos": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators"],
      "nivel_risco": "medio"
    },
    "Administrador de Sistemas": {
      "departamento": "IT",
      "conta_associada": "administrativa",
      "grupos_permitidos": ["GG-IT-Admins", "Domain Admins"],
      "grupos_proibidos": [],
      "nivel_risco": "critico"
    },
    "Tecnico de Recursos Humanos": {
      "departamento": "RecursosHumanos",
      "grupos_permitidos": ["GG-RH", "DL-Partilha-RH-Leitura", "DL-Partilha-RH-Escrita"],
      "grupos_proibidos": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators"],
      "nivel_risco": "medio"
    },
    "Analista Financeiro": {
      "departamento": "Financeira",
      "grupos_permitidos": ["GG-Financeira", "DL-Partilha-Financeira-Leitura"],
      "grupos_proibidos": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators"],
      "nivel_risco": "medio"
    },
    "Tecnico de Marketing": {
      "departamento": "Marketing",
      "grupos_permitidos": ["GG-Marketing", "DL-Partilha-Marketing-Leitura", "DL-Partilha-Marketing-Escrita"],
      "grupos_proibidos": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators"],
      "nivel_risco": "baixo"
    },
    "Tecnico de Operacoes": {
      "departamento": "Operacoes",
      "grupos_permitidos": ["GG-Operacoes", "DL-Partilha-Operacoes-Leitura"],
      "grupos_proibidos": ["Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators"],
      "nivel_risco": "baixo"
    }
  },
  "grupos_criticos": [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Backup Operators"
  ]
}
```

A lista de cargos acima é ilustrativa e cobre os seis departamentos
definidos em `01-arquitetura.md`; a lista final e completa é ajustada
quando `data/colaboradores.csv` for definido, de forma a que todo o Cargo
usado nesse ficheiro tenha uma entrada correspondente neste baseline (um
Cargo sem entrada é, por desenho, motivo para o script de onboarding
recusar a criação da conta em vez de assumir um conjunto de grupos por
omissão).

### 2.1. Campos

- **grupos_permitidos**: lista de grupos (globais, de domínio local, ou
  incorporados do AD como `Domain Admins`) que uma conta com este cargo
  pode legitimamente ter. Usado pelo script `03-Onboard-Users.ps1` para
  saber a que grupos adicionar uma conta nova.
- **grupos_proibidos**: lista de grupos que uma conta com este cargo nunca
  deve ter, independentemente de outras circunstâncias. Sempre que possível
  inclui, no mínimo, os cinco grupos críticos da secção 3. Esta lista é a
  que alimenta a deteção de desvios (secção 4): pertencer a um grupo
  proibido é sempre um desvio de alta prioridade, mesmo que o grupo não
  esteja em nenhuma das duas listas por omissão de manutenção do ficheiro.
- **nivel_risco**: classificação qualitativa (`baixo`, `medio`, `critico`)
  do impacto potencial se uma conta com este cargo for comprometida. Serve
  para priorizar a resposta a um desvio de privilégios: um desvio associado
  a um cargo `critico` (por exemplo, Administrador de Sistemas) merece
  investigação imediata; um desvio associado a um cargo `baixo` pode ser
  tratado com prioridade normal.
- **conta_associada** (campo opcional): indica quando o cargo corresponde,
  por natureza, a uma conta administrativa (`adm.primeiro.ultimo`) em vez
  de uma conta normal, reforçando a separação PAM descrita em
  `03-estrutura-ou-grupos.md`.

## 3. Grupos críticos do domínio

Os seguintes grupos incorporados do Active Directory são tratados como
**críticos** em todo o modelo de RBAC deste laboratório, independentemente
do cargo:

- **Domain Admins**: controlo administrativo total sobre o domínio
  `nortada.local`.
- **Enterprise Admins**: controlo administrativo total sobre toda a
  floresta (relevante mesmo numa floresta de um único domínio, porque
  concede direitos que ultrapassam o âmbito de um único domínio).
- **Schema Admins**: capacidade de alterar o esquema do Active Directory,
  uma alteração cujo impacto é irreversível sem restauro e afeta toda a
  floresta.
- **Account Operators**: capacidade de criar, modificar e eliminar a
  maioria das contas de utilizador e de grupo do domínio, um privilégio
  amplo frequentemente esquecido em auditorias focadas apenas em Domain
  Admins.
- **Backup Operators**: capacidade de contornar permissões de ficheiro
  para efeitos de cópia de segurança e restauro, o que na prática permite
  ler ou substituir praticamente qualquer ficheiro do sistema, incluindo a
  base de dados do AD.

Na baseline, a única entrada de cargo com permissão explícita para um
destes grupos críticos é "Administrador de Sistemas" (Domain Admins). Toda
e qualquer outra conta pertencente a um destes cinco grupos é, por
definição, um desvio de privilégios.

## 4. Uso como base de deteção de desvios no SentryLens

O ficheiro `data/rbac_baseline.json` é desenhado para ser consumido, num
passo futuro fora do âmbito deste laboratório de AD, por uma
funcionalidade do backend do SentryLens (`scripts/main.py`, no repositório
SentryLens) que:

1. Consulta periodicamente o Active Directory (ou os eventos de Security
   Group Management recolhidos via Wazuh, Event IDs 4728/4732 e
   4729/4733, ver `04-politica-auditoria.md`) para saber a que grupos cada
   conta de utilizador pertence atualmente.
2. Cruza essa pertença real com o `Cargo` do utilizador (atributo `Title`
   no AD, preenchido no onboarding conforme `05-onboarding-offboarding.md`)
   e a entrada correspondente em `rbac_baseline.json`.
3. Classifica cada diferença encontrada em dois tipos:
   - **Excesso de privilégio**: a conta pertence a um grupo que não consta
     de `grupos_permitidos` para o seu cargo, e com maior gravidade ainda
     se esse grupo constar de `grupos_proibidos` ou da lista de
     `grupos_criticos` da secção 3.
   - **Falta de privilégio**: a conta não pertence a um grupo listado em
     `grupos_permitidos` para o seu cargo (relevante sobretudo para
     deteção de erros de onboarding, menos crítico do ponto de vista de
     segurança do que o excesso).
4. Usa o `nivel_risco` do cargo para ordenar os desvios encontrados por
   prioridade de investigação no dashboard.

Esta funcionalidade de deteção no SentryLens não é implementada como parte
desta entrega de documentação: fica descrita aqui como o consumidor
pretendido do ficheiro `data/rbac_baseline.json`, a desenvolver num passo
posterior depois de o laboratório de AD estar operacional e a gerar dados
reais de pertença a grupos.

## 5. Relação com os outros documentos

- Os nomes de grupos globais e de domínio local usados neste documento
  seguem a convenção `GG-` e `DL-` definida em `03-estrutura-ou-grupos.md`.
- O `Cargo` (`Title`) usado como chave neste ficheiro é o mesmo campo
  preenchido pelo script `03-Onboard-Users.ps1` a partir de
  `data/colaboradores.csv`, conforme `05-onboarding-offboarding.md`.
- Os Event IDs de Security Group Management que tornam esta deteção
  possível dependem da Advanced Audit Policy ativada em
  `04-politica-auditoria.md`.
