# ad-pwsh-mod
A general purpose PowerShell module for common Active Directory system administration tasks.

## Installation

The module can be installed by running the following from an elevated PowerShell prompt:

`Install-Module -Name SysAdminPowerShellModule -Force`

### Pre-requisites

The module requires [the ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) to be installed.

### Examples

Here's how you can quickly and easily create a new Active Directory user using this module:

`New-OrgUser -Identity testuser -FirstName test -LastName test -Department test -Title 'senior tester'`
