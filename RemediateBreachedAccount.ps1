<#
.Synopsis 
	Use for when an Office 365 account has been compromised.
	
.Description
	The 'RemediateBreachedAccount.ps1' will remediate the attack to the accounts compromised and will remove any standing access to those accounts. It will perform the following actions:

	Revoke Microsoft Online session tokens
	Revoke OneDrive Session Tokens
	Enable Mailbox Auditing
	Remove Mailbox Delegates
	Disable Mailforwarding Rules To External Domains
	Remove MailboxForwarding
	Enable Multi-Factor Authentication (MFA) on the user's account (optional, un-comment 'Enable-MFA $upn' near the bottom)
	Set password complexity on the account to be high
	Reset the Password
	Produce an Audit Log for you to review

	Prerequisites:
		(More than I think are needed for this script, but you will need them for other work so, yes, go ahead with all of these)
		Install the Microsoft .NET Framework 4.5.x - https://docs.microsoft.com/en-us/dotnet/framework/install/guide-for-developers
		Install the Windows Management Framework 4.0 - https://www.microsoft.com/en-us/download/details.aspx?id=40855
		Install the Microsoft Online Services Sign-In Assistant for IT Professionals RTW - https://www.microsoft.com/en-us/download/details.aspx?id=41950
		Install the Azure Active Directory Connection - https://connect.microsoft.com/site1164/Downloads/DownloadDetails.aspx?DownloadID=59185
			Download and run the installer
			Open PowerShell as an Administrator
			Install-Module AzureAD
			Respond 'Y' to install the NuGet provider
			Allow the Untrusted repository 'PSGallery' by responding 'Y'
		Set-ExecutionPolicy RemoteSigned
	
.Parameter upn
	The User Principal Name, the Office 365 account of the affected user.  Usually this is their e-mail address, but may be an "onmicrosoft" address: "joeschmoe@uptimesciences.onmicrosoft.com"
	This is the "Username" from the Office 365 Active Users dashboard
	 
.Example
	RemediateBreachedAccount.ps1 joeschmoe@uptimesciences.com

.Notes
	Author : BKoeller
	WebSite: https://github.com/OfficeDev/O365-InvestigationTooling/commits?author=bkoeller
	Updates: Hal Noble - UpTime Sciences
	WebSite: https://github.com/halmonrye/office365management/blob/master/RemediateBreachedAccount.ps1
	Version: 0.5

	Future Ideas:
		Try something like:  Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString huku).objectId
		Update Groups?: Get-AzureADGroup -SearchString CloudSecGrp | Get-AzureADGroupMember | Revoke-AzureADUserAllRefreshToken
		Add more error checking as I have noticed that sometimes the Msol session does not always initiate.  Add session initiation checks and re-tries
		Modify to allow for Global Admins that have MFA turned on
		
	Updates
		2017-11-30 - hn - Added header, added and removed 'AllowClobber' on session imports, added session cleanupGet-Mailbox
		2017-12-06 - hn - Added SharePoint/OneDrive session revocation
		2017-12-18 - hn - Minor formatting and cleanup
		2018-01-22 - hn - Corrected two factor authentication reporting and added versioning - v0.5
#>

#Setup Initial Variables
#$upn = "sometestuser@a43999.onmicrosoft.com"

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)][ValidateNotNullOrEmpty()]
        [string]$upn
    
    #[Parameter(Mandatory=$False)]
    #    [date]$startDate,
    
    #[Parameter(Mandatory=$False)]
    #    [date]$endDate,
    
    #[Parameter(Mandatory=$False)]
    #    [string]$fromFile

)

$userName = $upn -split "@"

#Start Log Output
	$transcriptpath = ".\" + "RemediationTranscript" + "-" + (Get-Date).ToString('yyyy-MM-dd') + "-" + $userName[0] + ".txt"
	Start-Transcript -Path $transcriptpath

#Import Required Modules
	Import-Module MSOnline
	Import-Module SkypeOnlineConnector

#Get credentials
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Begin Remediating This Account: $upn"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Ask for credentials and connect to Office 365."
	$adminCredential = Get-Credential
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Credentials input.  Connecting to Office 365 as: ($adminCredential.UserName) "
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"

#Connect to services
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connect to Online Services"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") --------------------------"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connecting to Exchange Online Remote Powershell Service"
	$ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $adminCredential -Authentication Basic -AllowRedirection
	if ($null -ne $ExoSession) { 
		Import-PSSession $ExoSession
	} else {
		Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") No EXO service set up for this account"
	}
	Write-Output " "

	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connecting to EOP Powershell Service"
	$EopSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $adminCredential -Authentication Basic -AllowRedirection
	if ($null -ne $EopSession) { 
		Import-PSSession $EopSession
	} else {
		Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") No EOP service set up for this account"	
	}
	Write-Output " "

	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connecting to SharePoint Online Service"
	$SPODomain = $adminCredential.UserName -split "@"
	$SPODomain = $SPODomain[1]  -split "\."
	$SPODomain = $SPODomain[0]
	Connect-SPOService -Url https://$SPODomain-admin.sharepoint.com -credential $adminCredential
	Write-Output " "

	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connecting to Azure AD Service"
	Connect-AzureAD -Credential $adminCredential
	Write-Output " "
		
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connecting to Microsoft Online Services"
	Connect-MsolService -Credential $adminCredential
	Write-Output " "

	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connecting to Skype for Business Service"
	$sfboSession = New-CsOnlineSession -Credential $adminCredential
	Import-PSSession $sfboSession
	Write-Output " "

	#Load "System.Web" assembly in PowerShell console 
	[Reflection.Assembly]::LoadWithPartialName("System.Web") 
	Write-Output " "
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Connected to Online Services"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "

function Reset-Password($upn) {
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Reset Password"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") --------------"
    $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
    Set-MsolUserPassword -UserPrincipalName $upn -ForceChangePassword $True -NewPassword $newPassword	
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Password for the account $upn is now:   $newPassword"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon."
    
    Set-MsolUser -UserPrincipalName $upn -StrongPasswordRequired $True
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") We've also set this user's account to require a strong password."
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output " "
}

function Revoke-Tokens($upn) {
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Revoke Current Session Tokens"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") -----------------------------"
	$revokeID = (Get-msoluser -UserPrincipalName $upn | select -Expand ObjectID).ToString()
	Revoke-AzureADUserAllRefreshToken -ObjectID $revokeID
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") We've reset all session tokens for user: $upn"    
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "
}

function Revoke-OneDrive($upn) {
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Revoke Current OneDrive Connections"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") -----------------------------------"
	Revoke-SPOUserSession -User $upn -Confirm:$False
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") We've reset all OneDrive sessions for user: $upn"    
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output " "
}
 
function Enable-MailboxAuditing($upn) {
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Enable Mailbox Auditing"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ---------------------------"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Enabling mailbox auditing to ensure we can monitor activity going forward for user: $upn"

    #Let's enable auditing for the mailbox in question.
    Set-Mailbox $upn -AuditEnabled $true -AuditLogAgeLimit 365

    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Done! Here's the current configuration for auditing."    
    #Double-Check It!
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Current auditing configuration for user: $upn"
    Get-Mailbox -Identity $upn | Select Name, AuditEnabled, AuditLogAgeLimit
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "
}

function Remove-MailboxDelegates($upn) {
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Removing Mailbox Delegates"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") --------------------------"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Removing Mailbox Delegate Permissions for the affected user $upn."

    $mailboxDelegates = Get-MailboxPermission -Identity $upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}
    Get-MailboxPermission -Identity $upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}
    
    foreach ($delegate in $mailboxDelegates) 
    {
        Remove-MailboxPermission -Identity $upn -User $delegate.User -AccessRights $delegate.AccessRights -InheritanceType All -Confirm:$false
    }

    #Possibly add the admin running the script to the user's mailbox?
    #Add-MailboxPermission -Identity $upn -User $adminCredential.UserName -AccessRights FullAccess -InheritanceType All
    #TO DO: Need to figure out how to check delegate permissions set on a all the folders for the user, then remove them. Looks to be a user-only cmdlet permission set
    #$mailboxFolders = Get-MailboxFolder -Identity admin -Recurse
    #foreach ($folder in $mailboxFolders) 
    #{
    #    $thisUpnFolder = $upn + ":\" + $folder.FolderPath
    #    Get-MailboxFolderPermission -Identity $thisUpnFolder | Where-Object {($_.AccessRights -ne "None")}
        #Remove-MailboxFolderPermission: https://technet.microsoft.com/en-us/library/dd351181(v=exchg.160).aspx
    #}
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"    
	Write-Output " "
}

function Disable-MailforwardingRulesToExternalDomains($upn) {
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Disable Forwarding Rules"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ------------------------"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Disabling mailforwarding rules to external domains for the affected user $upn."
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") We found the following rules that forward or redirect mail to other accounts: "
    Get-InboxRule -Mailbox $upn | Select Name, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, SendTextMessageNotificationTo | Where-Object {(($_.Enabled -eq $true) -and (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) -or ($_.SendTextMessageNotificationTo -ne $null)))} | Format-Table
    Get-InboxRule -Mailbox $upn | Where-Object {(($_.Enabled -eq $true) -and (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) -or ($_.SendTextMessageNotificationTo -ne $null)))} | Disable-InboxRule -Confirm:$false

    #Clean-up disabled rules
    #Get-InboxRule -Mailbox $upn | Where-Object {((($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) -or ($_.SendTextMessageNotificationTo -ne $null)))} | Remove-InboxRule -Confirm:$false

    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Disabled all mailbox rules for user: $upn"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"    
	Write-Output " "
}

function Remove-MailboxForwarding($upn) {
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Removing Mailbox Forwarding"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ---------------------------"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Removing Mailbox Forwarding configurations for user: $upn"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Configuration before work is:"
    Get-Mailbox -Identity $upn | Select Name, DeliverToMailboxAndForward, ForwardingSmtpAddress

    Set-Mailbox -Identity $upn -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Mailbox forwarding removal completed for user:  $upn"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Configuration after work is:"
    Get-Mailbox -Identity $upn | Select Name, DeliverToMailboxAndForward, ForwardingSmtpAddress
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "
}

function Enable-MFA ($upn) {
    #Create the StrongAuthenticationRequirement object and insert required settings
    $mf = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
    $mf.RelyingParty = "*"
    $mfa = @($mf)
    #Enable MFA for a user
    Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationRequirements $mfa

    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Enabling Multi Factor Authentication"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ------------------------------------"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Enabled MFA required for user:  $upn"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") User will need to setup their additional authentication token the next time they logon."

    #Find all MFA enabled users
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Confirm Multi Factor Authentication is enabled for the affected user:"
    Get-MsolUser -UserPrincipalName $upn | select UserPrincipalName,StrongAuthenticationRequirements,StrongAuthenticationMethods
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Show Current list of all Multi Factor Authentication enabled users:"
    Get-MsolUser | select UserPrincipalName,StrongAuthenticationRequirements,StrongAuthenticationMethods | Where-Object {($_.StrongAuthenticationRequirements -ne $null)}
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "
}

function Get-AuditLog ($upn) {
    $userName = $upn -split "@"
    $auditLogPath = ".\" + $userName[0] + "AuditLog" + (Get-Date).ToString('yyyy-MM-dd') + ".csv"
    
    $startDate = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy') 
    $endDate = (Get-Date).ToString('MM/dd/yyyy')
    $results = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -UserIds $upn
    $results | Export-Csv -Path $auditLogPath

    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Getting Audit Log"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") -----------------"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") The account has been remediated, but there might be things we missed. Please review the audit transcript for this user to be super-sure you've covered everything."
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") The AuditLog has been written to: $auditLogPath"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") You can also review the activity below."
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    $results | Format-Table
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") End of Audit Log"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "

}

#Do the work
	Revoke-Tokens $upn
	Revoke-OneDrive $upn
	Enable-MailboxAuditing $upn
	Remove-MailboxDelegates $upn
	Disable-MailforwardingRulesToExternalDomains $upn
	Remove-MailboxForwarding $upn
	#Enable-MFA $upn
	Reset-Password $upn
	Get-AuditLog $upn

#Clean up
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") Clean Up Sessions"
	Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") -----------------"
	Remove-PSSession $EopSession
	Remove-PSSession $ExoSession
	Remove-PSSession $sfboSession
	# use 'Disconnect-PSSession ??
    Write-Output "$(Get-Date -UFormat "%Y-%m-%d_%H:%M:%S") ##############################################################"
	Write-Output " "

Stop-Transcript
#end