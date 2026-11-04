# Scripts de governança de endpoints

**English.** Read-only PowerShell 5.1+ scripts for a Windows fleet: endpoint inventory, installed software, allow/block compliance, version gold standards with a persistent remediation queue, local Administrators review, and protection evidence (Microsoft Defender, BitLocker, firewall profiles, pending reboot, and the last successful Windows Update). Results go to CSV, JSON, JSONL, or a self-contained HTML report. Samples use fictitious names such as `PC-EXAMPLE-01`. Running the scripts does not require external modules.

Scripts em PowerShell 5.1 ou superior para inventário de endpoints, conformidade de software, padrão de versão, revisão de administradores locais e evidência de proteção. A coleta é somente leitura. Os exemplos usam nomes fictícios, como `PC-EXAMPLE-01` e `LAPTOP-EXAMPLE-05`.

## Sobre

Repositório de portfólio de Celso da Silva Junior, especialista em infraestrutura de TI e governança de software, com 15 anos de atuação na administração de uma frota Windows de cerca de 22 mil endpoints. Os scripts são genéricos e mostram o tipo de controle usado nesse trabalho: saber o que existe, o que está instalado, o que foge da política e quem tem privilégio local. Não há dados de ambiente real.

## Para que servem

Em uma frota grande, a revisão periódica precisa de evidência repetível:

- quais máquinas existem e como estão configuradas
- qual software está instalado e se ele está permitido, proibido ou fora da lista
- qual versão está em uso diante de um padrão fixo ou calculado na própria frota
- quem é administrador local e se essa conta foi aprovada
- se a proteção do endpoint está ativa, o disco está criptografado, o firewall responde e a máquina ainda precisa reiniciar

Estes scripts fazem essa leitura com recursos nativos do Windows e gravam CSV, JSON ou HTML para uma pessoa revisar. Eles não removem software, não alteram grupos, não mudam firewall, BitLocker ou Defender e não instalam pacote nenhum.

## Conteúdo

| Caminho | Função |
| --- | --- |
| `scripts/Get-EndpointInventory.ps1` | Inventário de hardware e sistema via CIM |
| `scripts/Get-InstalledSoftware.ps1` | Software instalado nas chaves Uninstall de 32 e 64 bits |
| `scripts/Test-SoftwareCompliance.ps1` | Allow list, block list e software obrigatório |
| `scripts/Test-VersionCompliance.ps1` | Padrão-ouro de versão, fila de remediação e auditoria |
| `scripts/Get-LocalAdminAudit.ps1` | Membros do grupo Administradores local |
| `scripts/Get-EndpointSecurityStatus.ps1` | Defender, BitLocker, firewall, reboot e Windows Update |
| `scripts/Invoke-InventoryReport.ps1` | Consolida os coletores acima em CSV e HTML |
| `src/EndpointGovernance.psm1` | Regras testáveis, sem chamada remota |
| `samples/` | Políticas de exemplo e saída fictícia |
| `tests/` | Pester |
| `.github/workflows/powershell.yml` | PSScriptAnalyzer e Pester |

## Pré-requisitos

- Windows com Windows PowerShell 5.1 ou PowerShell 7
- Permissão de leitura em CIM, registro, grupo local e recursos de proteção
- Para outras máquinas: WinRM nos coletores que usam `Invoke-Command`; o inventário remoto usa CIM (Wsman ou Dcom)
- Para a suíte de testes: Pester 5 e PSScriptAnalyzer, instalados pelo workflow

Nenhum módulo externo é necessário para executar os scripts. A política de execução precisa permitir script local, por exemplo RemoteSigned.

```powershell
powershell.exe -NoProfile -File .\scripts\Get-EndpointInventory.ps1 -OutputPath .\output\endpoint-inventory.csv
```

A pasta `output/` é ignorada pelo Git.

## Uso rápido

```powershell
.\scripts\Get-EndpointInventory.ps1 -ComputerName PC-EXAMPLE-01, PC-EXAMPLE-02 -OutputPath .\output\endpoint-inventory.csv

.\scripts\Get-InstalledSoftware.ps1 -OutputPath .\output\installed-software.csv

.\scripts\Test-SoftwareCompliance.ps1 `
    -PolicyPath .\samples\software-policy.json `
    -InputPath .\output\installed-software.csv `
    -OutputPath .\output\software-compliance.csv

.\scripts\Test-VersionCompliance.ps1 `
    -InputPath .\samples\version-inventory.csv `
    -RulesPath .\samples\version-rules.json `
    -OutputPath .\output\version-compliance.csv

.\scripts\Get-LocalAdminAudit.ps1 `
    -ApprovedListPath .\samples\approved-admins.json `
    -OutputPath .\output\local-admin-audit.csv

.\scripts\Get-EndpointSecurityStatus.ps1 -MaxSignatureAgeDays 7 -OutputPath .\output\endpoint-security.csv

.\scripts\Invoke-InventoryReport.ps1 `
    -PolicyPath .\samples\software-policy.json `
    -ApprovedListPath .\samples\approved-admins.json `
    -OutputDirectory .\output
```

`-WhatIf` mostra o arquivo que seria gravado e não o cria. No gancho de versão, `-SubmitRemediation -WhatIf` também mostra quais itens sairiam de `pending` para `sent`, sem gravar a fila e sem implantar software.

```powershell
.\scripts\Test-VersionCompliance.ps1 `
    -InputPath .\samples\version-inventory.csv `
    -RulesPath .\samples\version-rules.json `
    -SubmitRemediation `
    -WhatIf
```

## Scripts

### Get-EndpointInventory.ps1

Lê, via CIM, nome, sistema e build, processador, memória, discos fixos, número de série, último boot, domínio e usuário logado. Aceita uma lista em `-ComputerName`. A consulta local não abre sessão. A consulta remota usa Wsman por padrão e pode usar `-CimProtocol Dcom`. Uma máquina que falha vira uma linha com `CollectionError`; as outras continuam.

### Get-InstalledSoftware.ps1

Lê as chaves Uninstall de 64 bits, 32 bits e do usuário atual. Devolve nome, versão, fabricante e data de instalação, além do escopo e da chave. Linhas sem nome são ignoradas. Componentes marcados como sistema ficam de fora, a menos que `-IncludeSystemComponents` seja usado. Duplicatas do mesmo nome, versão e fabricante ficam com a chave de 64 bits, depois a de 32 bits e por último a do usuário. `-ExcludePattern` recebe uma expressão regular, por exemplo `'KB\d+'`.

No remoto, a chave do usuário atual é o perfil da credencial da sessão, que pode não ser o usuário interativo.

### Test-SoftwareCompliance.ps1

Compara o inventário com um JSON de política. A ordem é:

1. Block list: `NonCompliant` / `Blocked`.
2. Allow list e, se couber, a lista de obrigatórios: confere `minVersion`.
3. Se o título não está em nenhuma lista: `Unknown` / `NotListed`.
4. Software obrigatório ausente: `NonCompliant` / `RequiredMissing`.

`Unknown` significa "não está na política". Não significa aprovado. Falha de coleta não gera um falso "ausente". Curingas `*` e `?` valem só quando aparecem no nome ou no fabricante; o resto é comparação exata, sem diferenciar maiúsculas.

### Test-VersionCompliance.ps1

Parte de um CSV com `hostname`, `software`, `version`, `os` e `online`. Também aceita os nomes `ComputerName`, `DisplayName`, `DisplayVersion` e `OperatingSystem`.

Cada regra tem:

- `gold`: versão fixa, ou `auto`
- `auto`: `most-common` (a mais frequente; empate fica com a mais nova) ou `latest`
- `tolerance`: folga aceita atrás do padrão
- `os`: filtros opcionais com curinga

Só máquinas online votam no padrão automático. Se nenhuma estiver online, entram as versões observadas. Uma máquina vota uma vez, pela versão mais alta que ela reportou.

O status de cada máquina, para cada software em escopo:

| Status | Quando |
| --- | --- |
| Compliant | Versão igual, mais nova ou dentro da tolerância |
| Outdated | Instalada, porém mais antiga do que a tolerância permite |
| Missing | Máquina online e sem o software |
| Unknown | Sem evidência suficiente: offline, versão ilegível, sistema conflitante ou padrão indefinido |

A tolerância soma componente a componente, sem "vai um". `122.0.0` com tolerância `0.0.5` é comparado ao padrão como `122.0.5`. Um número sozinho, como `1` diante de `6.2.0`, vale para o último componente (`0.0.1`). Versão igual ou mais nova que o padrão é Compliant.

A fila `remediation-queue.json` é persistente:

`pending` -> `sent` -> `confirmed` ou `abandoned`

- `Outdated` e `Missing` entram como `pending`
- `-SubmitRemediation` move `pending` para `sent`
- uma coleta posterior Compliant confirma o item
- se o problema voltar, o item confirmado reabre como `pending`
- `-AbandonId` abandona um item; abandonado não volta sozinho
- `deployed` permanece `false`: o gancho só registra a transição

O arquivo JSONL de auditoria acumula um retrato de cada execução. A execução seguinte compara com a anterior e preenche `delta`: `New`, `Unchanged`, `Improved`, `Regressed`, `Observed`, `Inconclusive` ou `Changed`. `Observed` é uma situação que deixou de ser `Unknown`. `Inconclusive` é o caminho inverso.

`-QueuePath ''` ou `-AuditPath ''` desliga o arquivo correspondente. Sem esses parâmetros, o padrão é `.\output\remediation-queue.json` e `.\output\version-audit.jsonl`.

### Get-LocalAdminAudit.ps1

Lista o grupo Administradores local pelo SID `S-1-5-32-544`, então o nome traduzido do Windows não importa. Se o cmdlet local não existir, usa o diretório de contas locais. Sem lista aprovada, o status fica `Unknown`. Lista vazia marca todo mundo como `Unapproved`. O arquivo `samples/approved-admins.json` traz `approvedAccounts`. Nome e SID aceitam curinga quando há `*` ou `?`.

### Get-EndpointSecurityStatus.ps1

Em cada máquina, lê o que for possível:

- serviço, antivírus e proteção em tempo real do Microsoft Defender, com idade da assinatura
- BitLocker por volume
- firewall de domínio, privado e público
- reinício pendente (Windows Update, Component Based Servicing, renomeação de arquivo, troca de nome do computador)
- data e título da última instalação bem-sucedida do Windows Update

Assinatura mais velha do que `-MaxSignatureAgeDays` (padrão 7) fica `Stale`. Idade igual ao limite continua `Current`. Uma falha em um sinal não apaga os outros: o texto vai para `CollectionError`.

### Invoke-InventoryReport.ps1

Roda os cinco coletores acima e grava, na pasta de saída:

- `endpoint-inventory.csv`
- `installed-software.csv`
- `software-compliance.csv`, se `-PolicyPath` for informado
- `local-admin-audit.csv`
- `endpoint-security.csv`
- `inventory-summary.csv`
- `inventory-summary.html`

O HTML não depende de site externo. A conformidade de versão fica de fora deste relatório porque o CSV de entrada é outro.

## Política de software

`samples/software-policy.json`:

```json
{
  "allow": [{ "name": "7-Zip", "publisher": "Igor Pavlov", "minVersion": "23.0.0" }],
  "block": [{ "name": "*Torrent*", "reason": "Peer-to-peer file sharing is not approved for workstations." }],
  "required": [{ "name": "Example Endpoint Agent", "publisher": "Example Security", "minVersion": "5.0.0" }]
}
```

Se o mesmo produto estiver na allow list e na lista de obrigatórios, as duas versões mínimas são conferidas. A block list ganha das outras.

## Práticas de governança

**Inventário.** `Get-EndpointInventory.ps1` sustenta o cadastro do ativo: qual é a máquina, qual build ela roda, quanto recurso tem, de qual domínio ela participa e quem estava logado na coleta.

**Conformidade de software.** A allow list diz o que pode estar presente. A block list diz o que não pode. A lista de obrigatórios aponta o que falta. `Unknown` é fila de revisão, não aprovação implícita.

**Conformidade de versão.** O padrão-ouro pode ser fixado ou calculado na frota. A tolerância evita tratar como desvio um atraso pequeno. A fila registra o tratamento sem implantar pacote, e o JSONL mostra o que mudou desde a coleta anterior.

**Revisão de acesso privilegiado.** `Get-LocalAdminAudit.ps1` compara o grupo Administradores local com uma lista aprovada. Conta fora da lista fica `Unapproved` para a revisão humana.

**Evidência de proteção.** Defender, BitLocker, firewall, reinício pendente e a última atualização formam um retrato para a revisão periódica. O relatório HTML junta esse retrato com o inventário, o software e os administradores.

## Exemplos fictícios

`samples/example-output/` traz CSV, HTML, fila e auditoria gerados com nomes como `PC-EXAMPLE-01`, `EXAMPLE.LOCAL` e `EXAMPLE-SERIAL-0001`. Não são máquinas, contas nem números de série reais. `samples/version-inventory.csv` e `samples/version-rules.json` são a entrada da amostra de versão: 17 achados, sendo 6 Compliant, 5 Outdated, 3 Missing e 3 Unknown na primeira execução (`delta` = `New`).

## Testes

```powershell
Import-Module Pester
$config = New-PesterConfiguration
$config.Run.Path = 'tests'
$config.Run.Exit = $true
Invoke-Pester -Configuration $config
```

Os testes cobrem a comparação de política, a escolha do padrão-ouro, a tolerância, a fila (`pending`, `sent`, `confirmed`, `abandoned`), o delta entre execuções e o gancho com `-WhatIf`. O workflow `.github/workflows/powershell.yml` roda PSScriptAnalyzer e Pester em `windows-latest`.

## Limitações

- Não altera configuração, grupo, software, firewall, BitLocker ou Defender.
- O gancho de remediação não implanta pacote. Ele só muda o estado da fila.
- Inventário remoto depende de CIM. Os outros coletores remotos dependem de WinRM.
- A chave Uninstall do usuário, no remoto, é a do perfil da credencial.
- Versão mínima da política de software usa até quatro componentes numéricos. A política de versão aceita qualquer quantidade de componentes numéricos no início do texto.
- `Unknown` não é aprovação.
- Os arquivos em `samples/` são fictícios.

## Licença

MIT. Copyright (c) 2026 Celso da Silva Junior. Veja [LICENSE](LICENSE).
