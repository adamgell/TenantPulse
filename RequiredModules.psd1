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

    # GraphKit is a runtime dependency (see source/TenantPulse.psd1 RequiredModules,
    # pinned to the same version) and is now published to PSGallery, so
    # Resolve-Dependency (PSResourceGet/PowerShellGet against PSGallery) resolves it here
    # like every other build dependency.
    GraphKit                    = '0.1.1'

    # GraphKit's own RequiredModules (transitive runtime dependencies). Resolve-Dependency
    # does NOT walk transitive requirements, and GraphKit's manifest demands these be
    # loadable at import - locally they happen to be installed, so only CI failed (every
    # matrix leg, at Import-Module time). Declare them explicitly, pinned to GraphKit
    # 0.1.1's own declared minima.
    'Microsoft.Graph.Authentication'        = '2.38.1'
    'Microsoft.PowerShell.SecretManagement' = '1.1.2'
}
