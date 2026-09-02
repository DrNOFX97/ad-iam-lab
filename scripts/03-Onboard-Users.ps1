#Requires -Version 5.1
<#
.SYNOPSIS
    Processa o onboarding em lote de colaboradores da Nortada Logistica no
    dominio nortada.local, a partir de data/colaboradores.csv.

.DESCRIPTION
    Implementa o processo de onboarding descrito em
    docs/05-onboarding-offboarding.md, seccao 2, depois de a arvore de OUs
    (01-New-OuStructure.ps1) e os grupos de seguranca (02-New-SecurityGroups.ps1)
    ja existirem no dominio.

    Para cada linha de data/colaboradores.csv (colunas: Nome, Apelido, Cargo,
    Departamento, Gestor, DataAdmissao, Email, Telefone, TipoConta,
    DepartamentoAnterior), o script:

    1. Determina o nome de utilizador (SamAccountName):
       - TipoConta "normal"        -> primeiro.ultimo (minusculas, sem acentos).
       - TipoConta "administrativa" -> adm.primeiro.ultimo.
       - TipoConta "servico"       -> derivado do Nome/Apelido da propria
         conta de servico (por exemplo Nome=Svc, Apelido=Backup ->
         svc.backup), sem qualquer prefixo "adm.".
    2. Determina a OU de destino: sub-OU de Departamento sob
       OU=Utilizadores,OU=NORTADA para contas normais;
       OU=Contas-Administrativas,OU=NORTADA para administrativas;
       OU=Contas-Servico,OU=NORTADA para contas de servico.
    3. Gera uma password inicial aleatoria como SecureString (nunca em texto
       simples persistido), com ChangePasswordAtLogon para contas normais e
       administrativas; contas de servico ficam com password sem expiracao e
       sem obrigatoriedade de mudanca (ver .NOTES).
    4. Preenche Department, Title, Manager (resolvido pelo nome do Gestor),
       EmailAddress e OfficePhone.
    5. Adiciona aos grupos de seguranca de acordo com
       data/rbac_baseline.json: procura o Cargo exato da linha; se nao
       encontrado, regista um aviso claro e NAO adiciona a conta a qualquer
       grupo por omissao (decisao de seguranca deliberada, ver .NOTES); se
       encontrado, adiciona apenas aos grupos_permitidos, nunca aos
       grupos_proibidos (uma entrada inconsistente com o mesmo grupo em
       ambas as listas leva a recusa dessa adicao especifica, com erro
       registado).
    6. Regista tudo num log CSV de auditoria em
       scripts/logs/onboarding-<data>.csv (DataHora, Utilizador,
       Departamento, Cargo, GruposAtribuidos, Resultado), alem do log de
       execucao em texto simples em scripts/logs/.

    O script e idempotente: se a conta (SamAccountName) ja existir, a
    criacao e ignorada com um aviso ("conta ja existe, ignorado"), sem tentar
    criar um objeto duplicado nem falhar de forma confusa. Uma segunda
    execucao sobre o mesmo CSV nao volta a tentar (re)atribuir grupos a
    contas ja existentes (ver Limitacoes em .NOTES).

.PARAMETER CaminhoCsv
    Caminho para o ficheiro data/colaboradores.csv. Por omissao,
    "..\data\colaboradores.csv", relativo a pasta scripts/ onde este script
    reside.

.PARAMETER CaminhoBaseline
    Caminho para o ficheiro data/rbac_baseline.json. Por omissao,
    "..\data\rbac_baseline.json", relativo a pasta scripts/.

.PARAMETER DomainDN
    Distinguished Name da raiz do dominio. Por omissao,
    "DC=nortada,DC=local".

.EXAMPLE
    .\03-Onboard-Users.ps1 -WhatIf

    Mostra que contas, atributos e pertencas a grupos seriam criados a
    partir de data/colaboradores.csv, sem alterar o Active Directory.
    Recomendado como primeira execucao para validar o CSV (departamentos,
    gestores e cargos desconhecidos) antes de qualquer escrita real.

.EXAMPLE
    .\03-Onboard-Users.ps1

    Executa o onboarding completo com os caminhos por omissao para o CSV e
    para o baseline de RBAC.

.EXAMPLE
    .\03-Onboard-Users.ps1 -CaminhoCsv "C:\dados\colaboradores.csv" -CaminhoBaseline "C:\dados\rbac_baseline.json"

    Executa o onboarding a partir de ficheiros num caminho alternativo.

.NOTES
    Decisoes de seguranca:
    - "Cargo desconhecido no baseline" nunca resulta em grupos atribuidos por
      omissao: e preferivel uma conta criada sem qualquer grupo de
      departamento (que o RH/IT tem de corrigir manualmente depois de
      atualizar data/rbac_baseline.json) do que uma conta criada com acessos
      adivinhados ou herdados de um cargo parecido, que poderia conceder
      acesso indevido sem qualquer decisao humana explicita. E o principio
      de "fail closed" aplicado a atribuicao de RBAC.
    - Uma entrada do baseline com o mesmo grupo em grupos_permitidos e em
      grupos_proibidos e tratada como um erro de configuracao do baseline, e
      nao como uma preferencia a resolver automaticamente: o script recusa
      essa adicao especifica e regista erro, para forcar a correcao manual
      do ficheiro rbac_baseline.json em vez de arriscar conceder (ou negar)
      um acesso sensivel com base numa ambiguidade.
    - Contas de servico (TipoConta=servico) ficam com PasswordNeverExpires e
      sem ChangePasswordAtLogon porque nao ha um utilizador humano para
      responder a um pedido de mudanca de password interactivo: uma
      expiracao de password numa conta de servico provoca uma paragem de
      servico assim que a password expira sem ninguem para a renovar
      interactivamente. A rotacao de password de contas de servico e, por
      isso, um processo manual e planeado, fora do ambito deste script.
    - A password inicial gerada nunca e escrita em texto simples em disco
      (ficheiro de log ou CSV de auditoria): e criada diretamente como
      SecureString com um gerador de numeros aleatorios criptografico
      (RandomNumberGenerator) e a variavel de texto simples intermedia,
      inevitavel para construir o SecureString em PowerShell, e limpa da
      memoria imediatamente a seguir a ser usada.
    - Este script nunca correu contra um dominio real; qualquer resumo ou
      resultado apresentado reflete apenas o que uma execucao concreta
      viesse a encontrar e criar, nunca um resultado inventado antecipadamente.

    Limitacoes conhecidas:
    - A idempotencia cobre a criacao da conta (nao volta a criar nem a
      falhar de forma confusa sobre uma conta existente), mas nao reconcilia
      atribuicoes de grupo numa segunda execucao: se o Cargo de uma linha
      mudar no CSV depois de a conta ja existir, os grupos nao sao
      automaticamente atualizados por este script.
    - A resolucao do Gestor e baseada em correspondencia exata do
      SamAccountName construido a partir do nome (primeiro.ultimo); nomes de
      gestor com mais de duas palavras usam apenas a primeira e a ultima
      palavra como primeiro nome e apelido.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$CaminhoCsv,

    [Parameter()]
    [string]$CaminhoBaseline,

    [Parameter()]
    [string]$DomainDN = "DC=nortada,DC=local"
)

# ---------------------------------------------------------------------------
# Preparacao do log de execucao
# ---------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($CaminhoCsv)) {
    $CaminhoCsv = Join-Path -Path $scriptDir -ChildPath "..\data\colaboradores.csv"
}
if ([string]::IsNullOrWhiteSpace($CaminhoBaseline)) {
    $CaminhoBaseline = Join-Path -Path $scriptDir -ChildPath "..\data\rbac_baseline.json"
}

$logDir = Join-Path -Path $scriptDir -ChildPath "logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$dataExecucao = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path -Path $logDir -ChildPath ("03-onboard-users-{0}.log" -f $dataExecucao)
$logCsvPath = Join-Path -Path $logDir -ChildPath ("onboarding-{0}.csv" -f (Get-Date -Format "yyyyMMdd"))

function Write-Log {
    param(
        [string]$Mensagem,
        [ValidateSet("INFO", "AVISO", "ERRO")]
        [string]$Nivel = "INFO"
    )
    $linha = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Nivel, $Mensagem
    Add-Content -Path $logFile -Value $linha
    switch ($Nivel) {
        "ERRO"  { Write-Error $Mensagem }
        "AVISO" { Write-Warning $Mensagem }
        default { Write-Host $linha }
    }
}

function Write-LogAuditoria {
    param(
        [string]$Utilizador,
        [string]$Departamento,
        [string]$Cargo,
        [string]$GruposAtribuidos,
        [string]$Resultado
    )
    $linhaAuditoria = [PSCustomObject]@{
        DataHora         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Utilizador       = $Utilizador
        Departamento     = $Departamento
        Cargo            = $Cargo
        GruposAtribuidos = $GruposAtribuidos
        Resultado        = $Resultado
    }
    $existeCsv = Test-Path -Path $logCsvPath
    $linhaAuditoria | Export-Csv -Path $logCsvPath -NoTypeInformation -Encoding UTF8 -Append:$existeCsv
}

Write-Log "Inicio da execucao do script 03-Onboard-Users.ps1."
Write-Log "Parametros: CaminhoCsv=$CaminhoCsv CaminhoBaseline=$CaminhoBaseline DomainDN=$DomainDN"

# ---------------------------------------------------------------------------
# Funcao auxiliar: remove acentos e normaliza para minusculas, para gerar
# nomes de utilizador consistentes com a convencao primeiro.ultimo.
# ---------------------------------------------------------------------------

function ConvertTo-NomeUtilizador {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Texto
    )
    if ([string]::IsNullOrWhiteSpace($Texto)) {
        return ""
    }
    $normalizado = $Texto.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($caractere in $normalizado.ToCharArray()) {
        $categoria = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($caractere)
        if ($categoria -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($caractere)
        }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC).ToLowerInvariant()
}

# ---------------------------------------------------------------------------
# Funcao auxiliar: gera uma password aleatoria criptograficamente segura,
# devolvida diretamente como SecureString.
# ---------------------------------------------------------------------------

function New-PasswordInicialSegura {
    param(
        [int]$Comprimento = 20
    )
    $carateres = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*'
    $bytesAleatorios = New-Object byte[] $Comprimento
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytesAleatorios)
    $passwordTexto = -join ($bytesAleatorios | ForEach-Object { $carateres[$_ % $carateres.Length] })
    $passwordSegura = ConvertTo-SecureString -String $passwordTexto -AsPlainText -Force
    # Limpa a variavel de texto simples intermedia assim que deixa de ser necessaria.
    $passwordTexto = $null
    return $passwordSegura
}

# ---------------------------------------------------------------------------
# Carregamento dos dados de entrada
# ---------------------------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Log "Nao foi possivel importar o modulo ActiveDirectory: $($_.Exception.Message)" -Nivel "ERRO"
    throw "O modulo ActiveDirectory (RSAT) tem de estar disponivel para correr este script."
}

if (-not (Test-Path -Path $CaminhoCsv)) {
    Write-Log "Ficheiro de colaboradores nao encontrado: $CaminhoCsv" -Nivel "ERRO"
    throw "Ficheiro de colaboradores nao encontrado: $CaminhoCsv"
}
if (-not (Test-Path -Path $CaminhoBaseline)) {
    Write-Log "Ficheiro de baseline RBAC nao encontrado: $CaminhoBaseline" -Nivel "ERRO"
    throw "Ficheiro de baseline RBAC nao encontrado: $CaminhoBaseline"
}

try {
    $colaboradores = Import-Csv -Path $CaminhoCsv -Encoding UTF8
}
catch {
    Write-Log "Falha ao ler o CSV de colaboradores '$CaminhoCsv': $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

try {
    $baseline = Get-Content -Path $CaminhoBaseline -Raw -Encoding UTF8 | ConvertFrom-Json
}
catch {
    Write-Log "Falha ao ler/interpretar o baseline RBAC '$CaminhoBaseline': $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# Departamentos validos, tal como definidos em 01-New-OuStructure.ps1.
$departamentosValidos = @("Direcao", "Financeira", "RecursosHumanos", "IT", "Marketing", "Operacoes")

# ---------------------------------------------------------------------------
# Processamento de cada linha do CSV
# ---------------------------------------------------------------------------

$script:contadorCriadas = 0
$script:contadorIgnoradas = 0
$script:contadorErros = 0

foreach ($linha in $colaboradores) {

    try {
        $nome = $linha.Nome
        $apelido = $linha.Apelido
        $cargo = $linha.Cargo
        $departamento = $linha.Departamento
        $tipoConta = $linha.TipoConta.Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($nome) -or [string]::IsNullOrWhiteSpace($apelido)) {
            Write-Log "Linha sem Nome/Apelido valido, a ignorar: $($linha | Out-String)" -Nivel "ERRO"
            $script:contadorErros++
            continue
        }

        $nomeNormalizado = ConvertTo-NomeUtilizador -Texto $nome
        $apelidoNormalizado = ConvertTo-NomeUtilizador -Texto $apelido
        $samBase = "$nomeNormalizado.$apelidoNormalizado"

        # Passo 1: determinar o SamAccountName conforme o TipoConta.
        switch ($tipoConta) {
            "normal" {
                $sam = $samBase
                $ouDestino = "OU=$departamento,OU=Utilizadores,OU=NORTADA,$DomainDN"
            }
            "administrativa" {
                $sam = "adm.$samBase"
                $ouDestino = "OU=Contas-Administrativas,OU=NORTADA,$DomainDN"
            }
            "servico" {
                # Para contas de servico, o proprio Nome/Apelido da linha ja
                # representa a identidade da conta de servico (por exemplo
                # Nome=Svc, Apelido=Backup -> svc.backup), sem prefixo "adm.".
                $sam = $samBase
                $ouDestino = "OU=Contas-Servico,OU=NORTADA,$DomainDN"
            }
            default {
                Write-Log "TipoConta '$($linha.TipoConta)' desconhecido para '$nome $apelido'. Linha ignorada." -Nivel "ERRO"
                $script:contadorErros++
                Write-LogAuditoria -Utilizador $samBase -Departamento $departamento -Cargo $cargo -GruposAtribuidos "" -Resultado "Erro: TipoConta desconhecido"
                continue
            }
        }

        # Validacao do departamento apenas para contas normais (as
        # administrativas e de servico usam OUs fixas independentes do
        # departamento indicado na linha).
        if ($tipoConta -eq "normal" -and ($departamentosValidos -notcontains $departamento)) {
            Write-Log "Departamento '$departamento' invalido para '$sam' (esperado um de: $($departamentosValidos -join ', ')). Linha ignorada." -Nivel "ERRO"
            $script:contadorErros++
            Write-LogAuditoria -Utilizador $sam -Departamento $departamento -Cargo $cargo -GruposAtribuidos "" -Resultado "Erro: departamento invalido"
            continue
        }

        # Passo idempotencia: a conta ja existe?
        $contaExistente = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
        if ($contaExistente) {
            Write-Log "Conta '$sam' ja existe. Ignorado (idempotencia): nenhuma alteracao efetuada." -Nivel "AVISO"
            $script:contadorIgnoradas++
            Write-LogAuditoria -Utilizador $sam -Departamento $departamento -Cargo $cargo -GruposAtribuidos "" -Resultado "Ignorado (conta ja existe)"
            continue
        }

        # Passo 3: password inicial aleatoria como SecureString.
        $passwordSegura = New-PasswordInicialSegura

        $exigirMudancaPassword = $true
        $passwordNuncaExpira = $false
        if ($tipoConta -eq "servico") {
            # Contas de servico: sem utilizador humano para mudar a password
            # interativamente, ver .NOTES.
            $exigirMudancaPassword = $false
            $passwordNuncaExpira = $true
        }

        # Passo 4: resolucao do Gestor pelo nome (se preenchido).
        $managerDN = $null
        $gestorTexto = $linha.Gestor
        if ([string]::IsNullOrWhiteSpace($gestorTexto)) {
            Write-Log "Linha de '$sam' sem Gestor definido (esperado para direcao de topo / contas de servico)." -Nivel "INFO"
        }
        else {
            $partesGestor = $gestorTexto.Trim() -split '\s+'
            $primeiroNomeGestor = $partesGestor[0]
            $apelidoGestor = $partesGestor[$partesGestor.Count - 1]
            $samGestor = "$(ConvertTo-NomeUtilizador -Texto $primeiroNomeGestor).$(ConvertTo-NomeUtilizador -Texto $apelidoGestor)"
            $contaGestor = Get-ADUser -Filter "SamAccountName -eq '$samGestor'" -ErrorAction SilentlyContinue
            if ($contaGestor) {
                $managerDN = $contaGestor.DistinguishedName
            }
            else {
                Write-Log "Gestor '$gestorTexto' (SamAccountName esperado '$samGestor') nao encontrado no AD para '$sam'. A continuar sem definir Manager." -Nivel "AVISO"
            }
        }

        # Passo 5: resolucao dos grupos de seguranca via rbac_baseline.json.
        $gruposParaAdicionar = @()
        $entradaBaseline = $baseline.cargos.($cargo)
        if (-not $entradaBaseline) {
            Write-Log "Cargo desconhecido no baseline: '$cargo' (utilizador '$sam'). Nenhum grupo sera atribuido por omissao (decisao de seguranca, ver .NOTES)." -Nivel "AVISO"
        }
        else {
            if ($entradaBaseline.PSObject.Properties.Name -contains "conta_associada" -and $entradaBaseline.conta_associada -and $entradaBaseline.conta_associada -ne $tipoConta) {
                Write-Log "Inconsistencia: cargo '$cargo' espera TipoConta '$($entradaBaseline.conta_associada)' no baseline, mas a linha do CSV tem TipoConta '$tipoConta' (utilizador '$sam')." -Nivel "AVISO"
            }
            $gruposPermitidos = @($entradaBaseline.grupos_permitidos)
            $gruposProibidos = @($entradaBaseline.grupos_proibidos)
            foreach ($grupo in $gruposPermitidos) {
                if ($gruposProibidos -contains $grupo) {
                    Write-Log "Baseline inconsistente para o cargo '$cargo': o grupo '$grupo' consta simultaneamente em grupos_permitidos e grupos_proibidos. Adicao recusada para '$sam'." -Nivel "ERRO"
                    $script:contadorErros++
                    continue
                }
                $gruposParaAdicionar += $grupo
            }
        }

        # Criacao da conta (respeita -WhatIf via SupportsShouldProcess).
        if ($PSCmdlet.ShouldProcess("$sam ($ouDestino)", "Criar utilizador AD")) {
            $parametrosNewAdUser = @{
                Name                  = "$nome $apelido"
                GivenName             = $nome
                Surname               = $apelido
                SamAccountName        = $sam
                UserPrincipalName     = "$sam@nortada.local"
                Path                  = $ouDestino
                AccountPassword       = $passwordSegura
                Enabled               = $true
                ChangePasswordAtLogon = $exigirMudancaPassword
                PasswordNeverExpires  = $passwordNuncaExpira
                Department            = $departamento
                Title                 = $cargo
                ErrorAction           = "Stop"
            }
            if (-not [string]::IsNullOrWhiteSpace($linha.Email)) {
                $parametrosNewAdUser["EmailAddress"] = $linha.Email
            }
            if (-not [string]::IsNullOrWhiteSpace($linha.Telefone)) {
                $parametrosNewAdUser["OfficePhone"] = $linha.Telefone
            }
            if ($managerDN) {
                $parametrosNewAdUser["Manager"] = $managerDN
            }

            New-ADUser @parametrosNewAdUser
            Write-Log "Conta '$sam' criada em '$ouDestino' (TipoConta=$tipoConta)."
            $script:contadorCriadas++

            $gruposAdicionadosComSucesso = @()
            foreach ($grupo in $gruposParaAdicionar) {
                if ($PSCmdlet.ShouldProcess("$grupo", "Adicionar '$sam' como membro")) {
                    try {
                        Add-ADGroupMember -Identity $grupo -Members $sam -ErrorAction Stop
                        Write-Log "Utilizador '$sam' adicionado ao grupo '$grupo'."
                        $gruposAdicionadosComSucesso += $grupo
                    }
                    catch {
                        Write-Log "Falha ao adicionar '$sam' ao grupo '$grupo': $($_.Exception.Message)" -Nivel "ERRO"
                        $script:contadorErros++
                    }
                }
            }

            Write-LogAuditoria -Utilizador $sam -Departamento $departamento -Cargo $cargo `
                -GruposAtribuidos ($gruposAdicionadosComSucesso -join ";") -Resultado "Sucesso"
        }
        else {
            Write-Log "ShouldProcess indicou -WhatIf: conta '$sam' nao foi criada. Grupos que seriam atribuidos: $($gruposParaAdicionar -join ', ')."
            Write-LogAuditoria -Utilizador $sam -Departamento $departamento -Cargo $cargo `
                -GruposAtribuidos ($gruposParaAdicionar -join ";") -Resultado "Simulado (-WhatIf)"
        }
    }
    catch {
        Write-Log "Erro ao processar a linha de '$($linha.Nome) $($linha.Apelido)': $($_.Exception.Message)" -Nivel "ERRO"
        $script:contadorErros++
        Write-LogAuditoria -Utilizador "$($linha.Nome) $($linha.Apelido)" -Departamento $linha.Departamento -Cargo $linha.Cargo `
            -GruposAtribuidos "" -Resultado "Erro: $($_.Exception.Message)"
        # Nao interrompe o lote: continua com a proxima linha do CSV.
        continue
    }
}

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------

$resumo = "Resumo: $script:contadorCriadas conta(s) criada(s), $script:contadorIgnoradas conta(s) ja existente(s) ignorada(s), $script:contadorErros erro(s)."
Write-Log $resumo
Write-Host $resumo

Write-Log "Log de auditoria CSV em: $logCsvPath"
Write-Log "Fim da execucao do script 03-Onboard-Users.ps1. Log completo em: $logFile"
