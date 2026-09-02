#Requires -Version 5.1
<#
.SYNOPSIS
    Instala as roles AD DS e DNS e promove a maquina NORTADA-DC01 a Controlador
    de Dominio de uma nova floresta nortada.local.

.DESCRIPTION
    Este script implementa a secao 3 de docs/02-instalacao-dc.md do
    laboratorio AD da Nortada Logistica, Lda. Corre localmente, dentro da VM
    NORTADA-DC01, com o Windows Server ja instalado (Windows Server 2022
    Evaluation, conforme docs/01-arquitetura.md), numa sessao PowerShell com
    privilegios de Administrador.

    Ordem de execucao:
      1. Verificacoes previas: privilegios elevados, se a maquina ja e um
         Controlador de Dominio, e existencia do adaptador de rede indicado.
      2. Configuracao de rede: IP estatico, mascara, gateway e DNS primario
         (127.0.0.1, ja que o DNS integrado no AD vai correr localmente).
      3. Instalacao das roles AD-Domain-Services e DNS, com as ferramentas de
         gestao (RSAT) associadas.
      4. Criacao da floresta nortada.local com Install-ADDSForest. A maquina
         reinicia automaticamente no final, como exigido pelo processo.
      5. Verificacao pos-promocao (Get-ADDomain, Resolve-DnsName, estado dos
         servicos NTDS e DNS), a correr numa execucao posterior ja depois do
         reinicio, dado que o proprio reinicio interrompe a sessao atual.

    Este script nao foi corrido contra nenhuma VM real. As mensagens de
    progresso descrevem o que o script faz quando executado; os resultados de
    verificacao ficam pendentes de uma execucao real e de validacao pelo
    utilizador.

.PARAMETER DomainName
    Nome de dominio FQDN da nova floresta. Por omissao, nortada.local, tal
    como definido em docs/01-arquitetura.md.

.PARAMETER NetBiosName
    Nome NetBIOS do dominio. Por omissao, NORTADA.

.PARAMETER StaticIP
    Endereco IPv4 estatico a atribuir ao adaptador de rede antes da promocao.
    Por omissao, 192.168.1.150.

.PARAMETER PrefixLength
    Comprimento do prefixo de sub-rede (CIDR), equivalente a mascara de
    sub-rede. Por omissao, 24 (255.255.255.0).

.PARAMETER DefaultGateway
    Gateway predefinido da rede (o router de casa). Por omissao,
    192.168.1.1, a confirmar no ambiente real do utilizador.

.PARAMETER InterfaceAlias
    Nome do adaptador de rede a configurar (por exemplo "Ethernet"). Nao tem
    valor por omissao fixo: se nao for indicado, o script lista os
    adaptadores disponiveis e pede confirmacao interativa, para evitar
    configurar por engano o adaptador errado.

.PARAMETER SafeModeAdministratorPassword
    Password do modo de restauro de servicos de diretorio (DSRM), como
    SecureString. Parametro obrigatorio, nunca aceite como texto simples.

.EXAMPLE
    $dsrm = Read-Host -Prompt "Password DSRM" -AsSecureString
    .\00-Install-DomainController.ps1 -InterfaceAlias "Ethernet" -SafeModeAdministratorPassword $dsrm

.EXAMPLE
    .\00-Install-DomainController.ps1 -DomainName "nortada.local" -NetBiosName "NORTADA" `
        -StaticIP "192.168.1.150" -PrefixLength 24 -DefaultGateway "192.168.1.1" `
        -InterfaceAlias "Ethernet" -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM")

.NOTES
    Decisao de arquitetura e seguranca:
    - O IP estatico e configurado ANTES da instalacao das roles, porque um
      Controlador de Dominio com IP dinamico e uma pratica desaconselhada: o
      AD e o DNS integrado dependem de um endereco estavel para que os
      restantes membros do dominio (e futuramente o agente Wazuh) o
      consigam localizar de forma consistente (ver docs/02-instalacao-dc.md,
      seccao 3.2).
    - A password de DSRM nunca e aceite como texto simples nem escrita no
      ficheiro de log, por se tratar de uma credencial de recuperacao
      critica do dominio.
    - O script recusa-se a promover uma maquina que ja e Controlador de
      Dominio, em vez de deixar Install-ADDSForest falhar de forma confusa a
      meio do processo.
    - Parametros em vez de valores fixos no corpo do script: ver
      docs/02-instalacao-dc.md, seccao 4, para a justificacao completa
      (reutilizacao, auditoria, prevencao de erros silenciosos, consistencia
      com os restantes scripts do laboratorio).
    - Este script so pode ser corrido uma vez de forma util sobre a mesma
      maquina (nao e idempotente por natureza: promover uma floresta nova
      duas vezes nao faz sentido), pelo que a verificacao previa de "ja e
      DC" substitui a idempotencia por uma recusa clara e explicita.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$DomainName = "nortada.local",

    [Parameter()]
    [string]$NetBiosName = "NORTADA",

    [Parameter()]
    [ValidateScript({ $_ -match '^(\d{1,3}\.){3}\d{1,3}$' })]
    [string]$StaticIP = "192.168.1.150",

    [Parameter()]
    [ValidateRange(1, 32)]
    [int]$PrefixLength = 24,

    [Parameter()]
    [ValidateScript({ $_ -match '^(\d{1,3}\.){3}\d{1,3}$' })]
    [string]$DefaultGateway = "192.168.1.1",

    [Parameter()]
    [string]$InterfaceAlias,

    [Parameter(Mandatory = $true)]
    [System.Security.SecureString]$SafeModeAdministratorPassword
)

# ---------------------------------------------------------------------------
# Preparacao do log de execucao
# ---------------------------------------------------------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path -Path $scriptDir -ChildPath "logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path -Path $logDir -ChildPath ("00-install-dc-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

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

Write-Log "Inicio da execucao do script 00-Install-DomainController.ps1."
Write-Log "Parametros: DomainName=$DomainName NetBiosName=$NetBiosName StaticIP=$StaticIP/$PrefixLength DefaultGateway=$DefaultGateway InterfaceAlias=$InterfaceAlias"
Write-Log "Nota: este script nunca correu contra uma VM real; as mensagens abaixo descrevem o comportamento previsto."

# ---------------------------------------------------------------------------
# 3.1 Verificacoes previas
# ---------------------------------------------------------------------------

try {
    Write-Log "A verificar privilegios de Administrador..."
    $identidadeAtual = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identidadeAtual)
    $ehAdministrador = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $ehAdministrador) {
        Write-Log "O script nao esta a correr com privilegios elevados. Termina sem alteracoes." -Nivel "ERRO"
        throw "E necessario correr este script numa sessao PowerShell como Administrador."
    }
    Write-Log "Privilegios de Administrador confirmados."
}
catch {
    Write-Log "Falha na verificacao de privilegios: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

try {
    Write-Log "A verificar se a maquina ja e um Controlador de Dominio..."
    $jaEhDC = $false

    $servicoNtds = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
    if ($null -ne $servicoNtds) {
        $jaEhDC = $true
    }

    if ($jaEhDC) {
        Write-Log "A maquina ja tem o servico NTDS instalado, ou seja, ja e (ou ja foi) um Controlador de Dominio. O script recusa-se a repetir a promocao." -Nivel "ERRO"
        throw "Promocao cancelada: esta maquina ja parece ser um Controlador de Dominio. Nao ha suporte para repetir Install-ADDSForest sobre a mesma maquina."
    }
    Write-Log "A maquina ainda nao e um Controlador de Dominio. Pode prosseguir."
}
catch {
    Write-Log "Falha na verificacao de estado de DC: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

try {
    Write-Log "A verificar adaptadores de rede disponiveis..."
    $adaptadores = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    if (-not $adaptadores -or $adaptadores.Count -eq 0) {
        Write-Log "Nao foi encontrado nenhum adaptador de rede ativo." -Nivel "ERRO"
        throw "Nao existe nenhum adaptador de rede com estado 'Up' nesta maquina."
    }

    if ([string]::IsNullOrWhiteSpace($InterfaceAlias)) {
        Write-Log "Parametro -InterfaceAlias nao indicado. A listar adaptadores para confirmacao interativa."
        Write-Host "Adaptadores de rede ativos encontrados:"
        $adaptadores | Format-Table -Property Name, InterfaceDescription, Status | Out-String | Write-Host

        $InterfaceAlias = Read-Host -Prompt "Indique o nome (Name) do adaptador de rede a configurar com o IP estatico"
        if ([string]::IsNullOrWhiteSpace($InterfaceAlias)) {
            Write-Log "Nenhum adaptador foi indicado pelo utilizador." -Nivel "ERRO"
            throw "E necessario indicar um adaptador de rede valido para prosseguir."
        }
    }

    $adaptadorEscolhido = $adaptadores | Where-Object { $_.Name -eq $InterfaceAlias }
    if (-not $adaptadorEscolhido) {
        Write-Log "O adaptador '$InterfaceAlias' nao foi encontrado entre os adaptadores ativos." -Nivel "ERRO"
        throw "Adaptador de rede '$InterfaceAlias' nao existe ou nao esta ativo."
    }
    Write-Log "Adaptador de rede confirmado: $InterfaceAlias."
}
catch {
    Write-Log "Falha na verificacao do adaptador de rede: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# 3.2 Configuracao de rede
# ---------------------------------------------------------------------------

try {
    if ($PSCmdlet.ShouldProcess($InterfaceAlias, "Configurar IP estatico $StaticIP/$PrefixLength, gateway $DefaultGateway e DNS 127.0.0.1")) {
        Write-Log "A configurar IP estatico no adaptador '$InterfaceAlias'..."

        # Remove enderecos IPv4 existentes configurados manualmente para evitar
        # conflitos com o novo endereco estatico.
        $enderecosExistentes = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($endereco in $enderecosExistentes) {
            Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $endereco.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }

        New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $StaticIP -PrefixLength $PrefixLength -DefaultGateway $DefaultGateway | Out-Null
        Write-Log "IP estatico $StaticIP/$PrefixLength atribuido, gateway $DefaultGateway definido."

        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ("127.0.0.1")
        Write-Log "DNS primario definido para 127.0.0.1 (o proprio DC, apos instalacao do DNS integrado)."
    }
    else {
        Write-Log "ShouldProcess indicou -WhatIf: configuracao de rede nao aplicada."
    }
}
catch {
    Write-Log "Falha na configuracao de rede: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# 3.3 Instalacao das roles AD DS e DNS
# ---------------------------------------------------------------------------

try {
    if ($PSCmdlet.ShouldProcess("Localhost", "Instalar roles AD-Domain-Services e DNS com ferramentas de gestao")) {
        Write-Log "A instalar as roles AD-Domain-Services e DNS, com ferramentas de gestao (RSAT)..."
        $resultadoInstalacao = Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools

        if (-not $resultadoInstalacao.Success) {
            Write-Log "Install-WindowsFeature reportou insucesso na instalacao das roles." -Nivel "ERRO"
            throw "A instalacao das roles AD-Domain-Services e DNS nao foi bem sucedida."
        }
        Write-Log "Roles AD-Domain-Services e DNS instaladas com sucesso. Reinicio pendente: $($resultadoInstalacao.RestartNeeded)."
    }
    else {
        Write-Log "ShouldProcess indicou -WhatIf: instalacao de roles nao aplicada."
    }
}
catch {
    Write-Log "Falha na instalacao das roles: $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# 3.4 Criacao da floresta nortada.local
# ---------------------------------------------------------------------------

try {
    if ($PSCmdlet.ShouldProcess($DomainName, "Promover a Controlador de Dominio de uma nova floresta (Install-ADDSForest)")) {
        Write-Log "A iniciar Install-ADDSForest para a floresta '$DomainName' (NetBIOS '$NetBiosName')..."
        Write-Log "Nivel funcional de floresta e dominio: WinThreshold (Windows Server 2016 ou superior), DNS integrado ativo."

        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetbiosName $NetBiosName `
            -SafeModeAdministratorPassword $SafeModeAdministratorPassword `
            -InstallDns:$true `
            -ForestMode "WinThreshold" `
            -DomainMode "WinThreshold" `
            -DatabasePath "C:\Windows\NTDS" `
            -LogPath "C:\Windows\NTDS" `
            -SysvolPath "C:\Windows\SYSVOL" `
            -NoRebootOnCompletion:$false `
            -Force:$true

        Write-Log "Install-ADDSForest concluido. A maquina vai reiniciar automaticamente, como exigido pelo processo de promocao."
    }
    else {
        Write-Log "ShouldProcess indicou -WhatIf: promocao a Controlador de Dominio nao aplicada."
    }
}
catch {
    Write-Log "Falha na criacao da floresta '$DomainName': $($_.Exception.Message)" -Nivel "ERRO"
    throw
}

# ---------------------------------------------------------------------------
# 3.5 Verificacao pos-promocao
# ---------------------------------------------------------------------------
# Nota: apos Install-ADDSForest a maquina reinicia e esta sessao PowerShell
# termina antes de chegar a este ponto na pratica. Este bloco fica preparado
# para ser corrido numa execucao seguinte (depois do reinicio), com o modulo
# ActiveDirectory ja disponivel, para confirmar o estado do dominio.

try {
    Write-Log "A tentar verificacao pos-promocao (relevante sobretudo numa execucao posterior ao reinicio)..."

    $servicoNtdsPos = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
    $servicoDnsPos = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

    if ($servicoNtdsPos) {
        Write-Log "Servico NTDS encontrado. Estado: $($servicoNtdsPos.Status)."
    }
    else {
        Write-Log "Servico NTDS ainda nao disponivel nesta sessao (provavelmente porque o reinicio ainda nao ocorreu)." -Nivel "AVISO"
    }

    if ($servicoDnsPos) {
        Write-Log "Servico DNS Server encontrado. Estado: $($servicoDnsPos.Status)."
    }
    else {
        Write-Log "Servico DNS Server ainda nao disponivel nesta sessao." -Nivel "AVISO"
    }

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $dominioAtual = Get-ADDomain -ErrorAction Stop
            Write-Log "Get-ADDomain confirmou o dominio: $($dominioAtual.DNSRoot) (NetBIOS: $($dominioAtual.NetBIOSName))."
        }
        catch {
            Write-Log "Get-ADDomain nao foi possivel nesta sessao: $($_.Exception.Message)" -Nivel "AVISO"
        }
    }
    else {
        Write-Log "Modulo ActiveDirectory ainda nao disponivel nesta sessao." -Nivel "AVISO"
    }

    try {
        $resolucaoDns = Resolve-DnsName -Name $DomainName -ErrorAction Stop
        Write-Log "Resolve-DnsName confirmou a resolucao de '$DomainName'."
    }
    catch {
        Write-Log "Resolve-DnsName nao conseguiu resolver '$DomainName' nesta sessao: $($_.Exception.Message)" -Nivel "AVISO"
    }

    Write-Log "Verificacao pos-promocao concluida nesta execucao. Se a maquina ainda nao reiniciou, corra novamente esta seccao depois do reinicio para confirmar o estado real."
}
catch {
    Write-Log "Falha inesperada na verificacao pos-promocao: $($_.Exception.Message)" -Nivel "ERRO"
}

Write-Log "Fim da execucao do script 00-Install-DomainController.ps1. Log completo em: $logFile"
