@{
    <#
        This is only required if you need to use the method PowerShellGet & PSDepend
        It is not required for PSResourceGet or ModuleFast (and will be ignored).
        See Resolve-Dependency.psd1 on how to enable methods.
    #>
    #PSDependOptions             = @{
    #    AddToPath  = $true
    #    Target     = 'output\RequiredModules'
    #    Parameters = @{
    #        Repository = 'PSGallery'
    #    }
    #}

    # Pinned to exact versions (post-review fix - these four were floating on 'latest',
    # meaning a fresh -ResolveDependency run could silently pull a newer build-tool
    # version than whatever last actually built/tested this repo, with no record of which
    # version that was). Pinned to each tool's currently-resolved version under
    # output/RequiredModules/ at the time of this fix.
    InvokeBuild                 = '5.14.23'
    PSScriptAnalyzer            = '1.25.0'
    Pester                      = '6.1.0'
    ModuleBuilder               = '3.2.18'
    ChangelogManagement         = '3.1.0'
    Sampler                     = '0.120.1'

    # GraphKit is a runtime dependency (see source/TenantPulse.psd1 RequiredModules),
    # and this restore pin matches that exact published runtime dependency. Local or
    # offline validation may stage the already-tested GraphKit package under
    # output/RequiredModules.
    GraphKit                    = '0.3.0'

    # Resolve-Dependency does not walk transitive requirements. GraphKit 0.3.0 still uses
    # Microsoft.Graph.Authentication as its MSAL delivery vehicle, so stage it explicitly.
    # SecretManagement is intentionally absent: GraphKit 0.3.0 resolves that optional
    # boundary lazily only when a persisted-vault operation is invoked.
    'Microsoft.Graph.Authentication' = '2.38.1'
}
