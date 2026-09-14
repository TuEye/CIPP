function Invoke-CippTestORCA107 {
    <#
    .SYNOPSIS
    End-user spam notification is enabled
    #>
    param($Tenant)

    try {
        $QuarantinePolicies = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'ExoQuarantinePolicy')
        $ContentFilterPolicies = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'ExoHostedContentFilterPolicy')
        $ContentFilterRules = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'ExoHostedContentFilterRule')

        if ($QuarantinePolicies.Count -eq 0 -or $ContentFilterPolicies.Count -eq 0) {
            Add-CippTestResult -TenantFilter $Tenant -TestId 'ORCA107' -TestType 'Identity' -Status 'Skipped' -ResultMarkdown 'No data found in database. This may be due to missing required licenses or data collection not yet completed.' -Risk 'Low' -Name 'End-user spam notification is enabled' -UserImpact 'Low' -ImplementationEffort 'Low' -Category 'Quarantine'
            return
        }

        $RelevantPolicies = @($ContentFilterPolicies | Where-Object {
                if ($_.Name -eq 'Default') {
                    return $true
                }

                # Preset security policies are intentionally excluded for now.
                # They need some extra handling, and current Standard/Strict presets already notify users about quarantined spam.
                if ($_.RecommendedPolicyType -in @('Standard', 'Strict')) {
                    return $false
                }

                $PolicyName = $_.Name
                return $null -ne ($ContentFilterRules | Where-Object {
                        $_.Name -eq $PolicyName -and
                        $_.State -eq 'Enabled' -and
                        ($_.SentTo -or $_.SentToMemberOf -or $_.RecipientDomainIs)
                    } | Select-Object -First 1)
            })

        if ($RelevantPolicies.Count -eq 0) {
            Add-CippTestResult -TenantFilter $Tenant -TestId 'ORCA107' -TestType 'Identity' -Status 'Skipped' -ResultMarkdown 'No relevant EOP anti-spam policies found in database.' -Risk 'Low' -Name 'End-user spam notification is enabled' -UserImpact 'Low' -ImplementationEffort 'Low' -Category 'Quarantine'
            return
        }

        $QuarantinePolicyUsage = [System.Collections.Generic.List[object]]::new()
        $ActionMappings = @(
            @{ Action = 'SpamAction'; Tag = 'SpamQuarantineTag'; Label = 'Spam' }
            @{ Action = 'HighConfidenceSpamAction'; Tag = 'HighConfidenceSpamQuarantineTag'; Label = 'High confidence spam' }
            @{ Action = 'BulkSpamAction'; Tag = 'BulkQuarantineTag'; Label = 'Bulk spam' }
        )

        foreach ($Policy in $RelevantPolicies) {
            foreach ($Mapping in $ActionMappings) {
                if ($Policy.($Mapping.Action) -eq 'Quarantine') {
                    $QuarantinePolicyUsage.Add([PSCustomObject]@{
                            AntiSpamPolicy       = $Policy.Name
                            Action               = $Mapping.Label
                            QuarantinePolicyName = [string]$Policy.($Mapping.Tag)
                        }) | Out-Null
                }
            }
        }

        $UsedQuarantinePolicies = [System.Collections.Generic.List[object]]::new()
        foreach ($QuarantinePolicyName in @($QuarantinePolicyUsage.QuarantinePolicyName | Select-Object -Unique)) {
            $QuarantinePolicy = $QuarantinePolicies | Where-Object { $_.Name -eq $QuarantinePolicyName } | Select-Object -First 1
            $UsedBy = @($QuarantinePolicyUsage | Where-Object { $_.QuarantinePolicyName -eq $QuarantinePolicyName } | ForEach-Object { "$($_.AntiSpamPolicy) ($($_.Action))" })
            $UsedQuarantinePolicies.Add([PSCustomObject]@{
                    Name       = if ([string]::IsNullOrWhiteSpace($QuarantinePolicyName)) { 'Not configured' } else { $QuarantinePolicyName }
                    ESNEnabled = if ($QuarantinePolicy) { [bool]($QuarantinePolicy.ESNEnabled -eq $true) } else { $false }
                    Found      = [bool]$QuarantinePolicy
                    UsedBy     = $UsedBy -join ', '
                }) | Out-Null
        }

        $FailedPolicies = @($UsedQuarantinePolicies | Where-Object { -not $_.ESNEnabled })

        if ($FailedPolicies.Count -eq 0) {
            $Status = 'Passed'
            $Result = [System.Text.StringBuilder]::new("All quarantine policies used by relevant EOP anti-spam actions have end-user spam notifications enabled.`n`n")
            if ($UsedQuarantinePolicies.Count -eq 0) {
                $null = $Result.Append('None of the relevant EOP anti-spam actions use quarantine.')
            } else {
                $null = $Result.Append("| Quarantine Policy | Used By |`n")
                $null = $Result.Append("|-------------------|---------|`n")
                foreach ($Policy in $UsedQuarantinePolicies) {
                    $null = $Result.Append("| $($Policy.Name) | $($Policy.UsedBy) |`n")
                }
            }
        } else {
            $Status = 'Failed'
            $Result = [System.Text.StringBuilder]::new("One or more quarantine policies used by relevant EOP anti-spam actions do not have end-user spam notifications enabled.`n`n")
            $null = $Result.Append("| Quarantine Policy | Used By | Status |`n")
            $null = $Result.Append("|-------------------|---------|--------|`n")
            foreach ($Policy in $FailedPolicies) {
                $PolicyStatus = if ($Policy.Found) { 'End-user notifications are disabled' } else { 'Policy not found' }
                $null = $Result.Append("| $($Policy.Name) | $($Policy.UsedBy) | $PolicyStatus |`n")
            }
            $null = $Result.Append("`n**Remediation:** Enable end-user spam notifications on each quarantine policy listed above.")
        }

        Add-CippTestResult -TenantFilter $Tenant -TestId 'ORCA107' -TestType 'Identity' -Status $Status -ResultMarkdown $Result -Risk 'Low' -Name 'End-user spam notification is enabled' -UserImpact 'Low' -ImplementationEffort 'Low' -Category 'Quarantine'

    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Tests' -tenant $Tenant -message "Failed to run test: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        Add-CippTestResult -TenantFilter $Tenant -TestId 'ORCA107' -TestType 'Identity' -Status 'Failed' -ResultMarkdown "Test failed: $($ErrorMessage.NormalizedError)" -Risk 'Low' -Name 'End-user spam notification is enabled' -UserImpact 'Low' -ImplementationEffort 'Low' -Category 'Quarantine'
    }
}
