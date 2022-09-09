#Requires -Module "ActiveDirectory"
using module ActiveDirectory

################################################
############## USER MGMT SECTION ###############
################################################

function Enable-OrgUser {

<#
.SYNOPSIS
    Enables the specified user account and moves them to the corresponding
    departmental OU in that department's DN, then displays confirmation of
    the account's enabled status.

.DESCRIPTION
    Enable-OrgUser is a function that allows Org sysadmins to enable users in
    Active Directory, automatically enabling and moving the user account to the
    Users OU for that specific department. The function outputs a table to
    confirm that the user has indeed been enabled and placed into the Users OU.

.PARAMETER Identity
    The username/SAMAccountName of the user to be enabled.

.EXAMPLE
     Enable-OrgUser -Identity testuser

.INPUTS
    None

.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser

.NOTES
    Author:  Jason A Katz
#>

    [CmdletBinding()]
    param (
        # Mandatory ADUSer object parameter
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $Identity
    )
    
    begin {
        Write-Verbose -Message "Staging user information and declare variables..."
        $user = Get-ADUser -Identity $Identity
        Write-Verbose -Message "Grabbing the user's DN, separating the first three RDN's, finally selecting the last RDN..."
        $targetpath = $user.distinguishedname -split ',',3 | Select-Object -Last 1
        #$collab = 
    }
    
    process {
        # We don't want to process any enabled users
        try {
            if ($user.enabled -eq $false) {
                Write-Verbose -Message "Attempting to enable user account..."
                Set-ADUser -Identity $user -Enabled $true
                Write-Verbose -Message "Moving the user object from disabled OU into the department parent Users container..."
                Move-ADObject -Identity $user.distinguishedname -TargetPath $targetpath
                Write-Verbose -Message "Generating output table..."
                Get-ADUser -Identity $Identity | Format-Table name,enabled,distinguishedname
                Write-Host "User successfully enabled!" -ForegroundColor Green
            }
            elseif ($user.enabled -eq $true -or $null -eq $user.enabled -and $user.distinguishedname -ne $targetpath) {
                Write-Verbose -Message "User already enabled. Moving to appropriate OU..."
                Move-ADObject -Identity $user.distinguishedname -TargetPath $targetpath
                Write-Verbose -Message "Generating output table..."
                Get-ADUser -Identity $Identity | Format-Table name,enabled,distinguishedname
                Write-Host "User successfully enabled!" -ForegroundColor Green
            }
            elseif ($user.enabled -eq $true -or $null -eq $user.enabled -and $user.distinguishedname -contains 'contractors') {
                Write-Verbose -Message "User already enabled. Moving to appropriate OU..."
                Move-ADObject -Identity $user.distinguishedname -TargetPath $targetpath
                Write-Verbose -Message "Generating output table..."
                Get-ADUser -Identity $Identity | Format-Table name,enabled,distinguishedname
                Write-Host "User successfully enabled!" -ForegroundColor Green
            }
            elseif ($user.enabled -eq $true -or $null -eq $user.enabled) {
                Write-Host "This user is already enabled!" -ForegroundColor Red
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "Error: User not found!" -ForegroundColor Red
        }
        catch {
            $thing = $Error[0]
            Write-Host "Error: $thing"
        }
    }
    
    end {
        
    }
}

function Disable-OrgUser {

<#
.SYNOPSIS
    Disables the specified user account and moves them to the corresponding
    Disabled OU in that department's DN, then displays confirmation of the
    account's disabled status.

.DESCRIPTION
    Disable-OrgUser is a function that allows Org sysadmins to disable users in
    Active Directory, automatically disabling and moving the user account to the
    Disabled OU for that specific department. The function outputs a table to
    confirm that the user has indeed been disabled and placed into the Disabled OU.

.PARAMETER Identity
    The username/SAMAccountName of the user to be disabled.

.EXAMPLE
     Disable-OrgUser -Identity testuser

.INPUTS
    None

.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser

.NOTES
    Author:  Jason A Katz
#>

    [CmdletBinding()]
    param (
        # Mandatory ADUSer object parameter
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $Identity
    )

    begin {
        # Declaring variables
        Write-Verbose -Message "Attempting to obtain the user object..."
        $user = Get-ADUser -Identity "$Identity"
        Write-Verbose -Message "Attempting to compile target OU..."
        $disabledprefix = "OU=Disabled,"
        Write-Verbose -Message "Grabbing the user's DN, separating the first two RDN's, finally selecting the last RDN..."
        $parentou = $user.distinguishedname -split ',',2 | Select-Object -Last 1
        $targetpath = $disabledprefix + $parentou
    }

    Process {
        # We don't want to process any disabled users
        try {
            if ($user.enabled -eq $true) {
                Set-ADUser -Identity $user -Enabled $false -ErrorAction Stop
                # Move the user object into the department's disabled OU.
                Move-ADObject -Identity $user.distinguishedname -TargetPath $targetpath
                Get-ADUser -Identity "$Identity" | Format-Table name,enabled,distinguishedname
                Write-Host "User successfully disabled!" -ForegroundColor Green
            }
            else {
                Write-Host "This user is already disabled!" -ForegroundColor Red
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "Error: User not found!" -ForegroundColor Red
        }
        catch {
            Write-Host "Error: $Error[0]"
        }
    }

    end {

    }
}

function Move-OrgUser {

<#
.SYNOPSIS
    Automatically places users into the Moves OU so they can be manipulated by
    other departmental sysadmins from within Org.

.DESCRIPTION
    Move-OrgUser is a function that allows Org sysadmins to move existing users
    to a shared OU in Active Directory, which is necessary for user account objects
    to be manipulated by other departmental sysadmins without compromising access
    between OUs. This is often neccessary when staff are moving between Departments.

.PARAMETER Identity
    The username/SAMAccountName of the user to be moved.

.EXAMPLE
     Move-OrgUser -Identity testuser

.INPUTS
    None

.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser

.NOTES
    Author:  Jason A Katz
#>

    [CmdletBinding()]
    param (
        # Mandatory ADUSer object parameter
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $Identity)
    
    begin {
        $movesou = "OU=Moves,OU=Departments,DC=Org,DC=com"
        $account = Get-ADUser -Identity $Identity
    }
    
    process {
        Write-Verbose -Message "Attempting to move user object..."
        Move-ADObject -Identity $account.distinguishedname -TargetPath $movesou
        Write-Verbose -Message "Attempting to generate output table..."
        Get-ADUser -Identity $account.samaccountname | Format-Table name,distinguishedname
    }
    
    end {
        
    }
}

function New-OrgUser {

<#
.SYNOPSIS
    Creates a new user in the Org department specified then outputs a table
    showing finalized new user details.

.DESCRIPTION
    New-OrgUser is a function that allows Org sysadmins to create new users in
    Active Directory, quickly populating prerequisite attributes and placing
    them automatically in the correct OU based on the Department parameter value.

.PARAMETER Identity
    The username/SAMAccountName of the new user.

.PARAMETER FirstName
    The first name of the new user.

.PARAMETER LastName
    The last name of the new user.

.PARAMETER Department
    The department of the new user. Current valid values are Exec, Accounting, Finance, HR,
    Facilities, and TEST. Values are case-insensitive.

.PARAMETER Title
    The title of the person for whom this account is being created. This is an optional
    value.

.EXAMPLE
     New-OrgUser -Identity testuser -FirstName test -LastName test -Department test -Title 'senior tester'

.INPUTS
    None

.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser

.NOTES
    Author:  Jason A Katz
#>
    
    [CmdletBinding()]
    param (
        # Mandatory parameters
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $Identity,
        [string]
        $FirstName,
        [string]
        $LastName,
        [ValidateSet('Exec','Accounting','Finance','HR','Facilities','TEST')]
        [string]
        $Department,
        # Non-mandatory parameters
        [Parameter(Mandatory=$false)]
        [string]
        $Title,
        [string]
        $Description
    )
    
    dynamicparam {
        if ($Department -eq 'Exec') {
            $deptpath = 'OU=Users,OU=Exec,OU=Departments,DC=Org,DC=com'
        }
        elseif (($Department -eq 'Finance') -or ($Department -eq 'Accounting')) {
            $deptpath = 'OU=Users,OU=Finance,OU=Departments,DC=Org,DC=com'
        }
        elseif ($Department -eq 'HR') {
            $deptpath = 'OU=Users,OU=HR,OU=Departments,DC=Org,DC=com'
        }
        elseif ($Department -eq 'Facilities') {
            $deptpath = 'OU=Users,OU=Facilities,OU=Departments,DC=Org,DC=com'
        }
        elseif ($Department -eq 'TEST') {
            $deptpath = 'OU=Test,OU=Users,OU=TEST,OU=Departments,DC=Org,DC=com'
        }
    }

    begin {
        # Stage user information and declare variables
        #$upn = "[$Identity]@Org.com"
    }
    
    process {
        # Try creating the new user account with parameters
        try {
            Write-Verbose -Message "Attempting to create new user from input parameters..."
            New-ADUser -Name $Identity -GivenName $FirstName -SamAccountName $Identity -Surname $LastName -DisplayName $FirstName+$LastName -UserPrincipalName "$Identity@Org.com" -Title $Title -Description $Description -Department $Department -Path $deptpath -OtherAttributes @{'mail'="$Identity@Org.com"}
            Write-Verbose -Message "Attempting to generate new user information table..."
            Get-ADUser -Identity $Identity -Properties * | Format-Table samaccountname,enabled,displayname,mail,created,distinguishedname

        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
            Write-Host: "Error: User [$Identity] already exists!"
        }
        catch {
            Write-Host "Error: [$Error[0]]''"
        }
    }
    
    end {
        
    }
}

function Set-OrgPassword {

    <#
    .SYNOPSIS
        Changes the password for a Org user account.
    
    .DESCRIPTION
        Set-OrgPassword is a function that allows Org sysadmins to securely and 
        quickly change user passwords in Active Directory.
    
    .PARAMETER Identity
        The username/SAMAccountName of the new user.
    
    .EXAMPLE
         New-OrgUser -Identity testuser -FirstName test -LastName test -Department test -Title 'senior tester'
    
    .INPUTS
        None
    
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    
    .NOTES
        Author:  Jason A Katz
    #>
    
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
        
    }
    
    end {
        
    }
}

################################################
######## CONFIGURATION MANAGER SECTION ########
################################################

function Import-OrgConfigMgr {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
    # Site configuration
    $SiteCode = "SiteCode" # Site code 
    $ProviderMachineName = "mecm.Org.com" # SMS Provider machine name

    # Customizations
    $initParams = @{}
    $initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
    #$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

    }
    
    process {
    # For manipulating MECM via PowerShell cmdlets .

    ########## Do not change anything below this line ##########

    # Import the ConfigurationManager.psd1 module 
    if($null -eq (Get-Module ConfigurationManager)) {
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
    }

    # Connect to the site's drive if it is not already present
    if($null -eq (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
    }

    # Set the current location to be the site code.
    Set-Location "$($SiteCode):\" @initParams
    }
    
    end {
        
    }
}