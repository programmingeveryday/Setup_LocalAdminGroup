#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------
$domainOne = "thomas.local"
$domainTwo = "it.thomas.local"
#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory



function Add-ComputerAdministratorsGroupMember
{
	[CmdletBinding(DefaultParameterSetName = 'Main',
				   SupportsShouldProcess = $true,
				   PositionalBinding = $false,
				   ConfirmImpact = 'Medium')]
	[Alias()]
	[OutputType([String])]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0,
				   ParameterSetName = 'Main')]
		[string]$ComputerName,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 1,
				   ParameterSetName = 'Main')]
		[string]$UserName
	)
	
	Process
	{
		
		
		$adComputer = Try
		{
			$ComputerDomainName = $domainOne
			Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			
		}
		catch
		{
			try
			{
				$ComputerDomainName = $domainTwo
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			}
			catch
			{
				$_; return
			}
		}
		if ($adComputer.Name)
		{
			 $("Found Computer AD Account: {0}`n" -f $adComputer.Name)
		}
		
		$adUser = try
		{
			$UserDomainName = $domainOne
			Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
		}
		catch
		{
			try
			{
				$UserDomainName = $domainTwo
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
			}
			catch
			{
				$_; return
			}
		}
		
		if ($adUser.Name)
		{
			 $("Found User AD Account: {0}`n" -f $adUser.Name)
		}
		
		
		$CBU = $adComputer.DistinguishedName.Split(",")[-4]
		
		
		$ExemptOU = try
		{
			(Get-ADOrganizationalUnit -Filter 'Name -like "Exempt"' -ErrorAction Stop -Server $ComputerDomainName |
				Where-Object { $_.DistinguishedName -like "*$CBU*" }).DistinguishedName
		}
		catch { $_ }
		
		$localComputerAdminGroup = "{0} Administrators" -f $adComputer.Name
		
		$exemptADGroup = try
		{
			Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
		}
		catch
		{
			try
			{
				New-ADGroup -Name $localComputerAdminGroup -GroupScope DomainLocal -Path $ExemptOU -ErrorAction Stop -Server $ComputerDomainName
				Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
			}
			catch { $_ }
		}
		
		try
		{
			$enableGPOGroup = Get-ADGroup -Identity 'Enable GPO - HKE Local Admin - Computer' -Server $ComputerDomainName -ErrorAction Stop
			try
			{
				if (!($enableGPOGroup | Get-ADGroupMember | Where-Object{$_.name -eq $adComputer.name}))
				{
					$enableGPOGroup | Add-ADGroupMember -Server $ComputerDomainName -Members $adComputer -ErrorAction Stop
					$("Added: {0} to `"{1}`"`n" -f $adComputer.name, $enableGPOGroup.name )
				}
				
			}catch{$_}
		}
		catch { $_ }
		
		$addedExemptADGroupMember = if ($adUser | Get-Member | Where-Object{ $_.TypeName -eq "Microsoft.ActiveDirectory.Management.ADUser" })
		{
			
			try
			{
				$groupMemebrs = $exemptADGroup | Get-ADGroupMember -ErrorAction Stop -Server $ComputerDomainName
				try
				{
					if (!($groupMemebrs | Where-Object{ $_.SamAccountName -eq $adUser.SamAccountName }))
					{
						$exemptADGroup | Add-ADGroupMember -Members $adUser -ErrorAction Stop -Server $ComputerDomainName					
						$exemptADGroup | Get-ADGroupMember -ErrorAction Stop -Server $ComputerDomainName
					}
					else { $groupMemebrs }
				}
				catch { $_ }
			}
			catch { $_ }
		}
		if ($exemptADGroup.Name)
		{
			 $("Administators Group Name: `"{0}`" setup in {1}`n" -f $exemptADGroup.Name, $ExemptOU)
		}
		else { $exemptADGroup }
		
		if ($addedExemptADGroupMember | Get-Member | Where-Object{ $_.TypeName -eq "Microsoft.ActiveDirectory.Management.ADPrincipal" })
		{
			
			$addedExemptADGroupMember.name | ForEach-Object{
				 $("{0} is a member of `"{1}`"`n" -f $_, $exemptADGroup.Name)
			}
		}
		else
		{
			 $("Issue Adding: {0} to membership of `"{1}`"`n" -f $adUser.Name, $exemptADGroup.Name)
		}
	}
}


function Remove-ComputerAdministratorsGroupMember
{
	[CmdletBinding(DefaultParameterSetName = 'Main',
				   SupportsShouldProcess = $true,
				   ConfirmImpact = 'Medium')]
	[Alias()]
	[OutputType([String])]
	Param
	(
		# Param1 help description
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0,
				   ParameterSetName = 'Main')]
		[string]$ComputerName,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 1,
				   ParameterSetName = 'Main')]
		[string]$UserName
	)
	
	Process
	{
		
		
		$adComputer = Try
		{
			$ComputerDomainName = $domainOne
			Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			
		}
		catch
		{
			try
			{
				$ComputerDomainName = $domainTwo
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			}
			catch
			{
				$_; return
			}
		}
		if ($adComputer.Name)
		{
			 $("Found Computer AD Account: {0}`n" -f $adComputer.Name)
		}
		
		$adUser = try
		{
			$UserDomainName = $domainOne
			Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
		}
		catch
		{
			try
			{
				$UserDomainName = $domainTwo
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
			}
			catch
			{
				$_; return
			}
		}
		
		if ($adUser.Name)
		{
			 $("Found User AD Account: {0}`n" -f $adUser.Name)
		}
		$CBU = $adComputer.DistinguishedName.Split(",")[-4]
		
		$localComputerAdminGroup = "{0} Administrators" -f $adComputer.Name
		
		$exemptADGroup = try
		{
			Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
		}
		catch { $_ }
		if ($exemptADGroup.Name)
		{
			try
			{
				if (Get-ADGroupMember $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName | Where-Object { $_.SamAccountName -eq $adUser.SamAccountName })
				{
					$exemptADGroup | Remove-ADGroupMember -Members $adUser -Confirm:$false -ErrorAction Stop
					 $("Removed {0} from AD group `"{1}`"`n" -f $adUser.Name, $exemptADGroup.Name)
				}
				else
				{
					 $("User {0} not found in AD group `"{1}`"`n" -f $adUser.Name, $exemptADGroup.Name)
				}
			}
			catch
			{
				$_
			}
		}
		else
		{
			 $("`"{0}`" is not found in {1}`n" -f $localComputerAdminGroup, $CBU)
		}
	}
}

function Search-ComputerAdministratorsGroupMember
{
	[CmdletBinding(DefaultParameterSetName = 'Main',
				   SupportsShouldProcess = $true,
				   ConfirmImpact = 'Medium')]
	[Alias()]
	[OutputType([String])]
	Param
	(
		# Param1 help description
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0,
				   ParameterSetName = 'Main')]
		[string]$ComputerName,
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 1,
				   ParameterSetName = 'Main')]
		[string]$UserName
	)
	
	Process
	{
		$adComputer = Try
		{
			$ComputerDomainName = $domainOne
			Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			
		}
		catch
		{
			try
			{
				$ComputerDomainName = $domainTwo
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			}
			catch
			{
				$_; return
			}
		}
		if ($adComputer.Name)
		{
			 $("Found Computer AD Account: {0}`n" -f $adComputer.Name)
		}
		
		$adUser = try
		{
			$UserDomainName = $domainOne
			Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
		}
		catch
		{
			try
			{
				$UserDomainName = $domainTwo
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
			}
			catch
			{
				$_; return
			}
		}
		
		if ($adUser.Name)
		{
			 $("Found User AD Account: {0}`n" -f $adUser.Name)
		}
		$CBU = $adComputer.DistinguishedName.Split(",")[-4]
		
		$localComputerAdminGroup = "{0} Administrators" -f $adComputer.Name
		
		$enableGPOGroup = Get-ADGroup -Identity 'Enable GPO - HKE Local Admin - Computer' -Server $ComputerDomainName -ErrorAction Stop
		try
		{
			if (!($enableGPOGroup | Get-ADGroupMember | Where-Object{ $_.name -eq $adComputer.name }))
			{
				$("!!!Computer: {0} not found in: `"{1}`"`n" -f $adComputer.name, $enableGPOGroup.name)
			}
			
		}
		catch { $_ }

	
		
		$exemptADGroup = try
		{
			Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
		}
		catch {  $("Group Not Found: `"{0}`" in {1}`n" -f $localComputerAdminGroup, $CBU) }
		if ($exemptADGroup.Name)
		{
			try
			{
				$groupMembers = Get-ADGroupMember $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
				
				
				$foundUser = $groupMembers | Where-Object { $_.SamAccountName -eq $adUser.SamAccountName }
				if ($foundUser.name)
				{
					 $("Found Member: {0} in AD group `"{1}`"`n" -f $foundUser.name, $exemptADGroup.Name)
				}
				else {  $("{0} is not a member of AD group: `"{1}`"`n" -f $adUser.name, $exemptADGroup.Name) }
				
				$foundOtherUsers = $groupMembers | Where-Object { $_.SamAccountName -ne $adUser.SamAccountName }
				if ($foundOtherUsers)
				{
					$foundOtherUsers | ForEach-Object{  $("Found other Member: {0} of AD group: `"{1}`"`n" -f $_.Name, $exemptADGroup.Name) }
				}
				
			}
			catch
			{
				$_
			}
		}
		else
		{
			 $("`"{0}`" is not found in {1}`n" -f $localComputerAdminGroup, $CBU)
		}
		
	}
	
}

