@{
    Id         = 'TP.INT.0008'
    Title      = 'Intune Multi Admin Approval policy configured'
    Category   = 'Intune.Governance'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('operationApprovalPolicies')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseMultiAdminApprovalConfigured'
    }
    Consulting = @{
        WhatItMeans  = 'Multi Admin Approval (MAA) access policies require that a SECOND administrator account approve a change before Intune applies it, for whichever resource type(s) the policy protects (Apps, Compliance policies, Configuration policies, Device actions [wipe/retire/delete], Role-based access control, Scripts, Tenant Configuration). MAA enforcement applies to both interactive admin-center changes and application-authenticated Graph API calls made by service principals/automation, once at least one access policy exists. This check confirms at least one MAA access policy is configured; it does not (and Maester''s own upstream check does not) evaluate which specific resource type(s) are actually protected.'
        WhyItMatters = 'With zero MAA policies, any single administrator account with the right RBAC permissions - including one that has been compromised via phishing, token theft, or an insider - can unilaterally deploy a PowerShell script to every managed device, push a new configuration/compliance policy, or wipe/retire/delete devices, with no second set of eyes and no delay. MAA is specifically Microsoft''s own mitigation for "a single compromised or careless admin account" scenario for exactly these high-impact operations; it is a defense-in-depth control on top of normal RBAC, not a substitute for it.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Multi Admin Approval > Access policies > Create - start with the highest-impact resource types for your environment (Scripts and Device actions are common first choices) and assign a dedicated approver security group.'
            'The approver group MUST be a security group (distribution lists, Microsoft 365 groups, and mail-enabled security groups silently fail to resolve) and must itself be assigned as a member group on an Intune RBAC role - an approver group that is not role-assigned has its members periodically removed.'
            'Be deliberate about a "Role" policy-type access policy: once active it protects RBAC role/assignment changes too, including the approver-group role assignment MAA itself depends on - configure every other MAA policy and verify RBAC assignments first to avoid a self-inflicted deadlock (Microsoft''s own guidance documents the delete-policy-and-wait-3-5-minutes recovery path if this happens).'
            'Confirm your tenant has at least two eligible administrator accounts (a requestor and a distinct approver) before rolling this out - MAA cannot function, and a request can never be approved, with only one qualifying admin.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/AccessPoliciesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0008--intune-multi-admin-approval-policy-configured'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/multi-admin-approval'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1096'; License = 'MIT' }
}
