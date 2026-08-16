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

    InvokeBuild                 = 'latest'
    PSScriptAnalyzer            = 'latest'
    Pester                      = '6.1.0'
    ModuleBuilder               = 'latest'
    ChangelogManagement         = 'latest'
    Sampler                     = '0.120.1'

    # NOTE: GraphKit is a runtime dependency (see source/TenantPulse.psd1 RequiredModules)
    # but is intentionally NOT listed here. GraphKit is not yet published to PSGallery, so
    # Resolve-Dependency (PSResourceGet/PowerShellGet against PSGallery) cannot resolve it
    # and the build would fail before it started. Once GraphKit is published this entry can
    # be added back.
}
