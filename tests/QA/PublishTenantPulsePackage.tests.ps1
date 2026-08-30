<#
    Tests scripts/Publish-TenantPulsePackage.ps1's core safety property: pack-first-then-
    verify. This script is not a module function - it is a standalone, param-block script
    invoked directly (Adam runs it by hand; nothing in the build/test/CI pipeline calls
    it) - so it is exercised here as a real subprocess (`pwsh -File`) against a throwaway
    fixture "repo" rather than dot-sourced or InModuleScope'd. That fixture reproduces
    exactly the directory shape the script's own $repoRoot-relative paths expect:

        <fixture>/scripts/Publish-TenantPulsePackage.ps1   (a copy of the real script)
        <fixture>/tests/QA/Assert-GateResult.ps1            (a copy of the real gate)
        <fixture>/output/module/TenantPulse/<version>/TenantPulse.psm1
        <fixture>/output/testResults/NUnitXml_*.xml + PesterObject_*.xml

    The NUnit/PesterObject test-result fixture is fabricated (not a real 1800+ test Pester
    run) with just enough shape - root attributes, one Passed test-suite, an empty
    Containers list - to satisfy Assert-GateResult.ps1's own whole-result gate, so these
    tests stay fast and independent of the real suite while still exercising the actual
    gate script the publish script actually calls. `total` below MUST track whatever
    -MinimumTests the copied Publish-TenantPulsePackage.ps1 actually passes to the gate
    (see that script's own $script:tenantPulseGateMinimumTests-tracking comment) - it is a
    fabricated count, not a real one, so nothing else re-derives it automatically.

    Focus: the digest-comparison logic (the one check that turns "publish only the
    already-tested artifact" from a procedural rule into something enforced) and the
    dry-run-by-default publish gate. Release-capable cases inject an isolated fake module
    named Microsoft.PowerShell.PSResourceGet through a fixture-only PSModulePath, so they
    exercise the real module-qualified command boundary without reaching PSGallery.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:realScriptPath = Join-Path $repoRoot 'scripts/Publish-TenantPulsePackage.ps1'
    $script:realGatePath = Join-Path $repoRoot 'tests/QA/Assert-GateResult.ps1'

    if (-not (Test-Path -LiteralPath $script:realScriptPath -PathType Leaf)) {
        throw "scripts/Publish-TenantPulsePackage.ps1 not found at '$script:realScriptPath'."
    }

    if (-not ('PulseMutatingConfirmationHost' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Security;

public sealed class PulseMutatingConfirmationHost : PSHost
{
    private readonly Guid instanceId = Guid.NewGuid();
    private readonly PulseMutatingConfirmationHostUi ui;

    public PulseMutatingConfirmationHost(string packagePath)
    {
        ui = new PulseMutatingConfirmationHostUi(packagePath);
    }

    public bool Prompted { get { return ui.Prompted; } }
    public override Guid InstanceId { get { return instanceId; } }
    public override string Name { get { return "PulseMutatingConfirmationHost"; } }
    public override Version Version { get { return new Version(1, 0); } }
    public override PSHostUserInterface UI { get { return ui; } }
    public override CultureInfo CurrentCulture { get { return CultureInfo.InvariantCulture; } }
    public override CultureInfo CurrentUICulture { get { return CultureInfo.InvariantCulture; } }
    public override void EnterNestedPrompt() { throw new NotSupportedException(); }
    public override void ExitNestedPrompt() { throw new NotSupportedException(); }
    public override void NotifyBeginApplication() { }
    public override void NotifyEndApplication() { }
    public override void SetShouldExit(int exitCode) { }
}

public sealed class PulseMutatingConfirmationHostUi : PSHostUserInterface
{
    private readonly string packagePath;

    public PulseMutatingConfirmationHostUi(string packagePath)
    {
        this.packagePath = packagePath;
    }

    public bool Prompted { get; private set; }
    public override PSHostRawUserInterface RawUI { get { return null; } }

    public override int PromptForChoice(
        string caption,
        string message,
        Collection<ChoiceDescription> choices,
        int defaultChoice)
    {
        Prompted = true;
        File.AppendAllText(packagePath, "MUTATED_DURING_CONFIRMATION");
        for (int i = 0; i < choices.Count; i++)
        {
            if (choices[i].Label.Replace("&", "").StartsWith("Yes", StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }
        return defaultChoice >= 0 ? defaultChoice : 0;
    }

    public override Dictionary<string, PSObject> Prompt(
        string caption,
        string message,
        Collection<FieldDescription> descriptions)
    {
        throw new NotSupportedException();
    }

    public override PSCredential PromptForCredential(
        string caption,
        string message,
        string userName,
        string targetName)
    {
        throw new NotSupportedException();
    }

    public override PSCredential PromptForCredential(
        string caption,
        string message,
        string userName,
        string targetName,
        PSCredentialTypes allowedCredentialTypes,
        PSCredentialUIOptions options)
    {
        throw new NotSupportedException();
    }

    public override string ReadLine() { return "Y"; }
    public override SecureString ReadLineAsSecureString() { return new SecureString(); }
    public override void Write(string value) { }
    public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value) { }
    public override void WriteDebugLine(string message) { }
    public override void WriteErrorLine(string value) { }
    public override void WriteLine() { }
    public override void WriteLine(string value) { }
    public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value) { }
    public override void WriteProgress(long sourceId, ProgressRecord record) { }
    public override void WriteVerboseLine(string message) { }
    public override void WriteWarningLine(string message) { }
}
'@
    }

    function Add-PulsePublishFixtureArchiveEntry {
        param(
            [Parameter(Mandatory)]
            [System.IO.Compression.ZipArchive] $Archive,

            [Parameter(Mandatory)]
            [string] $Name,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string] $Content
        )

        $entry = $Archive.CreateEntry($Name)
        $entryStream = $entry.Open()
        try {
            $writer = [System.IO.StreamWriter]::new($entryStream)
            try {
                $writer.Write($Content)
                $writer.Flush()
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $entryStream.Dispose()
        }
    }

    function Add-PulsePublishFixturePackageEntry {
        param(
            [Parameter(Mandatory)]
            [string] $PackagePath,

            [Parameter(Mandatory)]
            [string] $Name,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string] $Content
        )

        $archive = [System.IO.Compression.ZipFile]::Open($PackagePath, 'Update')
        try {
            Add-PulsePublishFixtureArchiveEntry -Archive $archive -Name $Name -Content $Content
        }
        finally {
            $archive.Dispose()
        }
    }

    function Set-PulsePublishFixturePackageEntry {
        param(
            [Parameter(Mandatory)]
            [string] $PackagePath,

            [Parameter(Mandatory)]
            [string] $Name,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string] $Content
        )

        $archive = [System.IO.Compression.ZipFile]::Open($PackagePath, 'Update')
        try {
            $entry = @($archive.Entries | Where-Object FullName -eq $Name)
            $entry.Count | Should -Be 1
            $entry[0].Delete()
            Add-PulsePublishFixtureArchiveEntry -Archive $archive -Name $Name -Content $Content
        }
        finally {
            $archive.Dispose()
        }
    }

    function Update-PulsePublishFixturePackageDigest {
        param(
            [Parameter(Mandatory)]
            [pscustomobject] $Fixture
        )

        $packageHash = (Get-FileHash -LiteralPath $Fixture.PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath $Fixture.PackageDigestPath `
            -Value "$(Split-Path -Leaf $Fixture.PackagePath)  $packageHash" `
            -NoNewline `
            -Encoding utf8

        $releaseProof = Get-Content -LiteralPath $Fixture.ReleaseProofPath -Raw | ConvertFrom-Json
        $releaseProof.package.sha256 = $packageHash
        $releaseProof | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $Fixture.ReleaseProofPath -NoNewline -Encoding utf8
    }

    function New-PulsePublishFixture {
        param(
            [string] $Version = '9.9.9',
            [string] $BuiltPsm1Content = "# built module content A`n",
            [string] $PackagedPsm1Content = "# built module content A`n",
            [string] $NuGetPackageModuleName = 'TenantPulse'
        )

        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('tp-publish-fixture-' + [guid]::NewGuid().ToString())

        $scriptsDir = Join-Path $fixtureRoot 'scripts'
        $gateDir = Join-Path $fixtureRoot 'tests/QA'
        $builtModuleDir = Join-Path $fixtureRoot "output/module/TenantPulse/$Version"
        $testResultsDir = Join-Path $fixtureRoot 'output/testResults'

        New-Item -ItemType Directory -Path $scriptsDir, $gateDir, $builtModuleDir, $testResultsDir -Force | Out-Null

        Copy-Item -LiteralPath $script:realScriptPath -Destination (Join-Path $scriptsDir 'Publish-TenantPulsePackage.ps1')
        Copy-Item -LiteralPath $script:realGatePath -Destination (Join-Path $gateDir 'Assert-GateResult.ps1')

        $builtPsm1Path = Join-Path $builtModuleDir 'TenantPulse.psm1'
        Set-Content -LiteralPath $builtPsm1Path -Value $BuiltPsm1Content -NoNewline -Encoding utf8
        $placeholderDir = Join-Path $builtModuleDir 'Data'
        New-Item -ItemType Directory -Path $placeholderDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $placeholderDir '.gitkeep') -Value '' -NoNewline -Encoding utf8

        # Digest manifest (post-review fix): the script now verifies against a manifest of
        # hashes recorded "at test time" rather than re-hashing whatever is currently on
        # disk - see Publish-TenantPulsePackage.ps1's own DIGEST-MANIFEST VERIFICATION
        # docstring section. This fixture writes one recorded from $BuiltPsm1Content, the
        # same content the built psm1 above was just given, so a test that wants to
        # reproduce "the build directory drifted after the digest was recorded" does so by
        # passing a DIFFERENT -BuiltPsm1Content after fixture creation (see the dedicated
        # test below), not by this helper disagreeing with itself.
        $digestManifestPath = Join-Path $testResultsDir 'tested-module-digest.txt'
        $builtPsm1Hash = (Get-FileHash -LiteralPath $builtPsm1Path -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath $digestManifestPath -Value "TenantPulse.psm1  $builtPsm1Hash" -NoNewline -Encoding utf8

        # A fabricated .nupkg with the two release-relevant records the publisher verifies:
        # the module payload and its package metadata.
        $packagePath = Join-Path $fixtureRoot "$NuGetPackageModuleName.$Version.nupkg"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($packagePath, 'Create')
        try {
            Add-PulsePublishFixtureArchiveEntry -Archive $archive `
                -Name "$NuGetPackageModuleName.psm1" `
                -Content $PackagedPsm1Content
            Add-PulsePublishFixtureArchiveEntry -Archive $archive `
                -Name "$NuGetPackageModuleName.nuspec" `
                -Content @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>$NuGetPackageModuleName</id>
    <version>$Version</version>
    <authors>Fixture</authors>
    <description>Publisher verification fixture.</description>
  </metadata>
</package>
"@
        }
        finally { $archive.Dispose() }

        # The test workflow records the exact archive hash after the suite has passed.
        # Every mutation test below changes the archive only after this proof is recorded.
        $packageDigestPath = Join-Path $testResultsDir 'tested-package-digest.txt'
        $packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath $packageDigestPath `
            -Value "$(Split-Path -Leaf $packagePath)  $packageHash" `
            -NoNewline `
            -Encoding utf8

        # A fabricated but gate-passing NUnit result + sibling PesterObject CLIXML, so
        # Assert-GateResult.ps1's own whole-result checks pass without a real 1800-test run.
        # total="2288" tracks scripts/Publish-TenantPulsePackage.ps1's own -MinimumTests
        # value (see this file's own header docstring) - bump both together.
        $resultPath = Join-Path $testResultsDir "NUnitXml_TenantPulse_v$Version.Fixture.xml"
        $nunitXml = @"
<?xml version="1.0" encoding="utf-8"?>
<test-results name="TenantPulse $Version" total="2288" failures="0" errors="0" skipped="0">
  <test-suite type="TestFixture" name="Fixture" result="Passed">
    <results>
      <test-case name="fixture test" result="Success" />
    </results>
  </test-suite>
</test-results>
"@
        Set-Content -LiteralPath $resultPath -Value $nunitXml -Encoding utf8

        $pesterObjectPath = Join-Path $testResultsDir "PesterObject_TenantPulse_v$Version.Fixture.xml"
        ([pscustomobject]@{ Containers = @() }) | Export-Clixml -LiteralPath $pesterObjectPath

        # One authoritative proof binds the package/module bytes to this exact NUnit and
        # Pester-object pair. The legacy text manifests remain fixture inputs for the
        # publisher's human-readable compatibility checks, not independent authority.
        $releaseProofPath = Join-Path $testResultsDir 'tested-release-proof.json'
        [pscustomobject] [ordered] @{
            schemaVersion = 1
            runId = [guid]::NewGuid().ToString('D')
            module = [pscustomobject] [ordered] @{
                name = 'TenantPulse'
                version = $Version
                files = @(
                    [pscustomobject] [ordered] @{
                        path = 'TenantPulse.psm1'
                        sha256 = $builtPsm1Hash
                    }
                )
            }
            package = [pscustomobject] [ordered] @{
                name = Split-Path -Leaf $packagePath
                sha256 = $packageHash
            }
            testRun = [pscustomobject] [ordered] @{
                nunit = [pscustomobject] [ordered] @{
                    name = Split-Path -Leaf $resultPath
                    sha256 = (Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                pesterObject = [pscustomobject] [ordered] @{
                    name = Split-Path -Leaf $pesterObjectPath
                    sha256 = (Get-FileHash -LiteralPath $pesterObjectPath -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        } | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $releaseProofPath -NoNewline -Encoding utf8

        [pscustomobject]@{
            FixtureRoot   = $fixtureRoot
            ScriptPath    = Join-Path $scriptsDir 'Publish-TenantPulsePackage.ps1'
            PackagePath   = $packagePath
            PackageDigestPath = $packageDigestPath
            ReleaseProofPath = $releaseProofPath
            ResultPath    = $resultPath
            PesterObjectPath = $pesterObjectPath
            BuiltPsm1Path = $builtPsm1Path
            Version       = $Version
        }
    }

    function Invoke-PulsePublishScript {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [string[]] $ExtraArgs = @()
        )

        $args = @(
            '-NoProfile', '-File', $Fixture.ScriptPath,
            '-PackagePath', $Fixture.PackagePath,
            '-TestResultPath', $Fixture.ResultPath
        ) + $ExtraArgs

        $output = & pwsh @args 2>&1 | Out-String
        [pscustomobject]@{
            Output   = $output
            ExitCode = $LASTEXITCODE
        }
    }

    function New-PulseFakePsResourceGetModule {
        param(
            [Parameter(Mandatory)]
            [pscustomobject] $Fixture
        )

        $modulesRoot = Join-Path $Fixture.FixtureRoot 'fixture-modules'
        $moduleDir = Join-Path $modulesRoot 'Microsoft.PowerShell.PSResourceGet/99.0.0'
        New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null

        $modulePath = Join-Path $moduleDir 'Microsoft.PowerShell.PSResourceGet.psm1'
        Set-Content -LiteralPath $modulePath -Encoding utf8 -Value @'
function Publish-PSResource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $NupkgPath,
        [Parameter(Mandatory)] [string] $Repository,
        [Parameter(Mandatory)] [string] $ApiKey
    )

    if (-not [string]::Equals($ApiKey, $env:TP_EXPECTED_API_KEY, [System.StringComparison]::Ordinal)) {
        throw 'FAKE_PSRESOURCEGET_RECEIVED_WRONG_KEY'
    }

    [pscustomobject]@{
        NupkgPath = $NupkgPath
        Repository = $Repository
        ApiKeyAccepted = $true
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $env:TP_FAKE_PUBLISH_TRACE -NoNewline -Encoding utf8
}

Export-ModuleMember -Function Publish-PSResource
'@

        New-ModuleManifest `
            -Path (Join-Path $moduleDir 'Microsoft.PowerShell.PSResourceGet.psd1') `
            -RootModule 'Microsoft.PowerShell.PSResourceGet.psm1' `
            -ModuleVersion '99.0.0' `
            -PowerShellVersion '7.4' `
            -FunctionsToExport @('Publish-PSResource')

        [pscustomobject]@{
            ModulesRoot = $modulesRoot
            TracePath = Join-Path $Fixture.FixtureRoot 'fake-publish-trace.json'
        }
    }
}

Describe 'Publish-TenantPulsePackage: pack-first-then-verify digest check' {
    AfterEach {
        if ($script:fixture) {
            Remove-Item -LiteralPath $script:fixture.FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'stays in dry run (no publish attempted, exit 0) when the packaged psm1 matches the tested build byte-for-byte' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'DRY RUN'
        $result.Output | Should -Match 'explicit operator action'
        # Distinct from the dry-run report's own "Nothing was published." sentence: this
        # checks for the SUCCESS line ("Published <module> <version> to <repo>") that only
        # a real Publish-PSResource call would print, which none of these tests trigger.
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses when the single bound release-proof manifest is missing' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"
        Remove-Item -LiteralPath $script:fixture.ReleaseProofPath -Force

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'tested release proof'
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses a separately supplied same-version passing result instead of authorizing it by version alone' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"
        $alternateDir = Join-Path $script:fixture.FixtureRoot 'alternate-results'
        New-Item -ItemType Directory -Path $alternateDir | Out-Null
        $alternateResultPath = Join-Path $alternateDir (Split-Path -Leaf $script:fixture.ResultPath)
        $alternatePesterPath = Join-Path $alternateDir (Split-Path -Leaf $script:fixture.PesterObjectPath)
        Copy-Item -LiteralPath $script:fixture.ResultPath -Destination $alternateResultPath
        Add-Content -LiteralPath $alternateResultPath -Value '<!-- separately supplied passing result -->'
        Copy-Item -LiteralPath $script:fixture.PesterObjectPath -Destination $alternatePesterPath
        $script:fixture.ResultPath = $alternateResultPath

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'NUnit result bound by the tested release proof'
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses when the Pester object in the bound result pair changes after proof creation' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"
        ([pscustomobject]@{ Containers = @(); Marker = 'changed after proof' }) |
            Export-Clixml -LiteralPath $script:fixture.PesterObjectPath

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Pester object bound by the tested release proof'
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses (non-zero exit, no dry-run report) when the packaged psm1 differs from the tested build' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "tested build content`n" -PackagedPsm1Content "rebuilt-after-test content`n"

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'NOT the one the tests ran against'
        $result.Output | Should -Not -Match 'DRY RUN'
    }

    It 'refuses an extra untested module payload even when the exact archive digest itself matches' {
        $script:fixture = New-PulsePublishFixture
        Add-PulsePublishFixturePackageEntry `
            -PackagePath $script:fixture.PackagePath `
            -Name 'unrecorded.ps1' `
            -Content "throw 'untested payload executed'"
        Update-PulsePublishFixturePackageDigest -Fixture $script:fixture

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'package archive'
        $result.Output | Should -Match 'untested payload'
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses a duplicate path even when the exact archive digest itself matches' {
        $script:fixture = New-PulsePublishFixture
        Add-PulsePublishFixturePackageEntry `
            -PackagePath $script:fixture.PackagePath `
            -Name 'TenantPulse.psm1' `
            -Content "throw 'duplicate untested module entry'"
        Update-PulsePublishFixturePackageDigest -Fixture $script:fixture

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'package archive'
        $result.Output | Should -Match 'duplicate entry'
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses when the nuspec is altered after the test proof was recorded' {
        $script:fixture = New-PulsePublishFixture
        Set-PulsePublishFixturePackageEntry `
            -PackagePath $script:fixture.PackagePath `
            -Name 'TenantPulse.nuspec' `
            -Content @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>AlteredPackageIdentity</id>
    <version>9.9.9</version>
    <authors>Fixture</authors>
    <description>Altered after tests.</description>
  </metadata>
</package>
"@

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'package archive'
        $result.Output | Should -Match 'test proof'
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses when a file the digest manifest recorded is missing from the built module directory' {
        $script:fixture = New-PulsePublishFixture
        Remove-Item -LiteralPath $script:fixture.BuiltPsm1Path -Force

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        # Exact file-set validation runs before per-file hashes, so a missing recorded
        # path is reported by the same set-drift guard as an unrecorded path.
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'TenantPulse\.psm1'
        $result.Output | Should -Match 'file\s*set\s*differs'
    }
    It 'refuses when the built module contains an unrecorded file' {
        $script:fixture = New-PulsePublishFixture
        $extraPath = Join-Path (Split-Path $script:fixture.BuiltPsm1Path -Parent) 'unrecorded.txt'
        Set-Content -LiteralPath $extraPath -Value 'not in the tested digest' -NoNewline -Encoding utf8

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'unrecorded\.txt'
        $result.Output | Should -Match 'digest'
    }
    It 'refuses when the tested and built file sets differ only by path case' {
        $script:fixture = New-PulsePublishFixture
        $digestManifestPath = Join-Path $script:fixture.FixtureRoot 'output/testResults/tested-module-digest.txt'
        $digestLine = (Get-Content -LiteralPath $digestManifestPath -Raw) -replace '^TenantPulse\.psm1', 'tenantpulse.psm1'
        Set-Content -LiteralPath $digestManifestPath -Value $digestLine -NoNewline -Encoding utf8

        $tokens = $parseErrors = $null
        $publisherAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:realScriptPath,
            [ref] $tokens,
            [ref] $parseErrors
        )
        $parseErrors.Count | Should -Be 0
        $compareCommands = @($publisherAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'Compare-Object'
        }, $true))
        $compareCommands.Count | Should -Be 1
        $compareCommands[0].Extent.Text | Should -Match '\-CaseSensitive\b'

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'tenantpulse\.psm1'
        $result.Output | Should -Match 'file\s*set\s*differs'
    }



    It 'refuses when no tested-module digest manifest is present at all' {
        $script:fixture = New-PulsePublishFixture
        $digestManifestPath = Join-Path $script:fixture.FixtureRoot 'output/testResults/tested-module-digest.txt'
        Remove-Item -LiteralPath $digestManifestPath -Force

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'No tested-module digest manifest found'
    }

    It 'refuses when the package name is not TenantPulse' {
        $script:fixture = New-PulsePublishFixture -NuGetPackageModuleName 'SomeOtherModule'
        # Re-point PackagePath is unnecessary - New-PulsePublishFixture already named the
        # .nupkg after -NuGetPackageModuleName.

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        # PowerShell wraps a thrown error's rendered message across terminal-width lines
        # (inserting its own '|' continuation markers), so match the distinguishing
        # fragments independently rather than a single contiguous phrase.
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match "is 'SomeOtherModule'"
        $result.Output | Should -Match 'not\s*(\||\s)*\s*TenantPulse'
    }

    It 'refuses when no -TestResultPath is given and -SkipTestProof is not either' {
        $script:fixture = New-PulsePublishFixture

        $args = @('-NoProfile', '-File', $script:fixture.ScriptPath, '-PackagePath', $script:fixture.PackagePath)
        $output = & pwsh @args 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        $exitCode | Should -Not -Be 0
        $output | Should -Match 'A -TestResultPath is required'
    }

    It 'skips both test-proof and digest verification under -SkipTestProof, warning loudly, and still stays dry-run without -NuGetApiKey' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content 'A' -PackagedPsm1Content 'DIFFERENT'

        $args = @('-NoProfile', '-File', $script:fixture.ScriptPath, '-PackagePath', $script:fixture.PackagePath, '-SkipTestProof')
        $output = & pwsh @args 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        $exitCode | Should -Be 0
        $output | Should -Match 'UNVERIFIED MECHANICS DRY RUN'
        $output | Should -Match 'DRY RUN'
    }

    It 'forces -SkipTestProof to stay dry-run even when an API key and non-interactive confirmation are supplied' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content 'A' -PackagedPsm1Content 'DIFFERENT'
        $oldApiKey = $env:TENANTPULSE_NUGET_API_KEY
        $oldScriptPath = $env:TP_PUBLISH_SCRIPT_PATH
        $oldPackagePath = $env:TP_PUBLISH_PACKAGE_PATH
        try {
            $env:TENANTPULSE_NUGET_API_KEY = 'fixture-key-never-sent'
            $env:TP_PUBLISH_SCRIPT_PATH = $script:fixture.ScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $script:fixture.PackagePath
            $output = & pwsh -NoProfile -Command @'
function Publish-PSResource { throw 'PUBLISH_CALLED' }
& $env:TP_PUBLISH_SCRIPT_PATH -PackagePath $env:TP_PUBLISH_PACKAGE_PATH -SkipTestProof -Publish -Confirm:$false
'@ 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
        }
        finally {
            $env:TENANTPULSE_NUGET_API_KEY = $oldApiKey
            $env:TP_PUBLISH_SCRIPT_PATH = $oldScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $oldPackagePath
        }

        $exitCode | Should -Be 0
        $output | Should -Match 'DRY RUN: -SkipTestProof'
        $output | Should -Not -Match 'PUBLISH_CALLED'
        $output | Should -Not -Match 'Published TenantPulse'
    }

    It 'requires explicit -Publish authorization even when an API key and -Confirm:$false are supplied' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"
        $oldApiKey = $env:TENANTPULSE_NUGET_API_KEY
        $oldScriptPath = $env:TP_PUBLISH_SCRIPT_PATH
        $oldPackagePath = $env:TP_PUBLISH_PACKAGE_PATH
        $oldResultPath = $env:TP_PUBLISH_RESULT_PATH
        try {
            $env:TENANTPULSE_NUGET_API_KEY = 'fixture-key-never-sent'
            $env:TP_PUBLISH_SCRIPT_PATH = $script:fixture.ScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $script:fixture.PackagePath
            $env:TP_PUBLISH_RESULT_PATH = $script:fixture.ResultPath
            $output = & pwsh -NoProfile -Command @'
function Publish-PSResource { throw 'PUBLISH_CALLED' }
& $env:TP_PUBLISH_SCRIPT_PATH -PackagePath $env:TP_PUBLISH_PACKAGE_PATH -TestResultPath $env:TP_PUBLISH_RESULT_PATH -Confirm:$false
'@ 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
        }
        finally {
            $env:TENANTPULSE_NUGET_API_KEY = $oldApiKey
            $env:TP_PUBLISH_SCRIPT_PATH = $oldScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $oldPackagePath
            $env:TP_PUBLISH_RESULT_PATH = $oldResultPath
        }

        $exitCode | Should -Be 0
        $output | Should -Match 'DRY RUN'
        $output | Should -Match 'explicit -Publish authorization'
        $output | Should -Not -Match 'PUBLISH_CALLED'
        $output | Should -Not -Match 'Published TenantPulse'
    }

    It 'uses the module-qualified PSResourceGet command so a caller function cannot intercept the plaintext key or fake success' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"
        $fakeModule = New-PulseFakePsResourceGetModule -Fixture $script:fixture
        $oldApiKey = $env:TENANTPULSE_NUGET_API_KEY
        $oldScriptPath = $env:TP_PUBLISH_SCRIPT_PATH
        $oldPackagePath = $env:TP_PUBLISH_PACKAGE_PATH
        $oldResultPath = $env:TP_PUBLISH_RESULT_PATH
        $oldExpectedApiKey = $env:TP_EXPECTED_API_KEY
        $oldTracePath = $env:TP_FAKE_PUBLISH_TRACE
        $oldModulePath = $env:PSModulePath
        try {
            $env:TENANTPULSE_NUGET_API_KEY = 'fixture-key-never-sent'
            $env:TP_PUBLISH_SCRIPT_PATH = $script:fixture.ScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $script:fixture.PackagePath
            $env:TP_PUBLISH_RESULT_PATH = $script:fixture.ResultPath
            $env:TP_EXPECTED_API_KEY = $env:TENANTPULSE_NUGET_API_KEY
            $env:TP_FAKE_PUBLISH_TRACE = $fakeModule.TracePath
            $env:PSModulePath = $fakeModule.ModulesRoot + [System.IO.Path]::PathSeparator + $oldModulePath
            $output = & pwsh -NoProfile -Command @'
function Import-Module {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string[]] $Name
    )

    Microsoft.PowerShell.Core\Import-Module -Name $Name -ErrorAction Stop
    Set-Item -Path Function:\global:Publish-PSResource -Value {
        [CmdletBinding()]
        param(
            [string] $NupkgPath,
            [string] $Path,
            [string] $Repository,
            [string] $ApiKey
        )
        if ([string]::Equals($ApiKey, $env:TP_EXPECTED_API_KEY, [System.StringComparison]::Ordinal)) {
            throw 'CALLER_INTERCEPTED_PLAINTEXT_KEY'
        }
        throw 'CALLER_INTERCEPTED_PUBLISH_COMMAND'
    }
}
. $env:TP_PUBLISH_SCRIPT_PATH -PackagePath $env:TP_PUBLISH_PACKAGE_PATH -TestResultPath $env:TP_PUBLISH_RESULT_PATH -Publish -Confirm:$false
'@ 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
        }
        finally {
            $env:TENANTPULSE_NUGET_API_KEY = $oldApiKey
            $env:TP_PUBLISH_SCRIPT_PATH = $oldScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $oldPackagePath
            $env:TP_PUBLISH_RESULT_PATH = $oldResultPath
            $env:TP_EXPECTED_API_KEY = $oldExpectedApiKey
            $env:TP_FAKE_PUBLISH_TRACE = $oldTracePath
            $env:PSModulePath = $oldModulePath
        }

        $output | Should -Not -Match 'CALLER_INTERCEPTED'
        $exitCode | Should -Be 0
        Test-Path -LiteralPath $fakeModule.TracePath -PathType Leaf | Should -BeTrue
        $trace = Get-Content -LiteralPath $fakeModule.TracePath -Raw | ConvertFrom-Json
        $trace.NupkgPath | Should -Be $script:fixture.PackagePath
        $trace.Repository | Should -Be 'PSGallery'
        $trace.ApiKeyAccepted | Should -BeTrue
    }

    It 'refuses an archive changed while the operator confirmation is in progress' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"
        $fakeModule = New-PulseFakePsResourceGetModule -Fixture $script:fixture
        $oldApiKey = $env:TENANTPULSE_NUGET_API_KEY
        $oldScriptPath = $env:TP_PUBLISH_SCRIPT_PATH
        $oldPackagePath = $env:TP_PUBLISH_PACKAGE_PATH
        $oldResultPath = $env:TP_PUBLISH_RESULT_PATH
        $oldExpectedApiKey = $env:TP_EXPECTED_API_KEY
        $oldTracePath = $env:TP_FAKE_PUBLISH_TRACE
        $oldModulePath = $env:PSModulePath
        $runspace = $null
        $powerShell = $null
        try {
            $env:TENANTPULSE_NUGET_API_KEY = 'fixture-key-never-sent'
            $env:TP_PUBLISH_SCRIPT_PATH = $script:fixture.ScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $script:fixture.PackagePath
            $env:TP_PUBLISH_RESULT_PATH = $script:fixture.ResultPath
            $env:TP_EXPECTED_API_KEY = $env:TENANTPULSE_NUGET_API_KEY
            $env:TP_FAKE_PUBLISH_TRACE = $fakeModule.TracePath
            $env:PSModulePath = $fakeModule.ModulesRoot + [System.IO.Path]::PathSeparator + $oldModulePath

            $mutatingHost = [PulseMutatingConfirmationHost]::new($script:fixture.PackagePath)
            $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($mutatingHost)
            $runspace.Open()
            $powerShell = [System.Management.Automation.PowerShell]::Create()
            $powerShell.Runspace = $runspace
            $null = $powerShell.AddScript(@'
& $env:TP_PUBLISH_SCRIPT_PATH -PackagePath $env:TP_PUBLISH_PACKAGE_PATH -TestResultPath $env:TP_PUBLISH_RESULT_PATH -Publish -Confirm
'@)
            try {
                $null = $powerShell.Invoke()
                $hadErrors = $powerShell.HadErrors
                $errorText = @($powerShell.Streams.Error | ForEach-Object {
                    $_.Exception.Message
                }) -join [System.Environment]::NewLine
            }
            catch {
                $hadErrors = $true
                $errorMessages = @($powerShell.Streams.Error | ForEach-Object {
                    $_.Exception.Message
                })
                $errorMessages += $_.Exception.Message
                $errorText = $errorMessages -join [System.Environment]::NewLine
            }
        }
        finally {
            if ($powerShell) { $powerShell.Dispose() }
            if ($runspace) { $runspace.Dispose() }
            $env:TENANTPULSE_NUGET_API_KEY = $oldApiKey
            $env:TP_PUBLISH_SCRIPT_PATH = $oldScriptPath
            $env:TP_PUBLISH_PACKAGE_PATH = $oldPackagePath
            $env:TP_PUBLISH_RESULT_PATH = $oldResultPath
            $env:TP_EXPECTED_API_KEY = $oldExpectedApiKey
            $env:TP_FAKE_PUBLISH_TRACE = $oldTracePath
            $env:PSModulePath = $oldModulePath
        }

        $mutatingHost.Prompted | Should -BeTrue
        $hadErrors | Should -BeTrue
        $errorText | Should -Match 'changed after confirmation'
        Test-Path -LiteralPath $fakeModule.TracePath | Should -BeFalse
    }

    It 'never publishes (stays dry-run) even when -Confirm is passed, if -NuGetApiKey is not' {
        $script:fixture = New-PulsePublishFixture

        $result = Invoke-PulsePublishScript -Fixture $script:fixture -ExtraArgs @('-Confirm:$false')

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'DRY RUN'
    }
}

Describe 'Publisher workflow boundary' {
    It 'does not expose Sampler gallery publication as a build workflow that bypasses the verified-package script' {
        $buildYaml = Get-Content -LiteralPath (Join-Path $script:repoRoot 'build.yaml') -Raw
        $buildYaml | Should -Not -Match '(?m)^  publish:\s*$'

        $publishWorkflow = [regex]::Match(
            $buildYaml,
            '(?ms)^  publish:\s*$(?<body>.*?)(?=^  [a-zA-Z0-9_.-]+:\s*$|^#{10,})'
        )

        $publishWorkflow.Success | Should -BeFalse
        $buildYaml | Should -Match '(?m)^SkipPublish:\s*true\s*$'
    }
}
