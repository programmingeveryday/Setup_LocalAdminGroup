#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------
$domainOne = "thomas.local"
$domainTwo = "it.thomas.local"
$global:dateToRemove = Get-Date 




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
			if (!$global:Credential)
			{
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			}
			else
			{
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
			}
		}
		catch
		{
			try
			{
				$ComputerDomainName = $domainTwo
				if (!$global:Credential)
				{
					Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
				}
				else
				{
					Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
				}
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
			if (!$global:Credential)
			{
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
			}
			else
			{
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName -Credential $global:Credential
			}
			
		}
		catch
		{
			try
			{
				$UserDomainName = $domainTwo
				if (!$global:Credential)
				{
					Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
				}
				else
				{
					
					Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName -Credential $global:Credential
				}
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
			if (!$global:Credential)
			{
				(Get-ADOrganizationalUnit -Filter 'Name -like "Exempt"' -ErrorAction Stop -Server $ComputerDomainName |
					Where-Object { $_.DistinguishedName -like "*$CBU*" }).DistinguishedName
			}
			else
			{
				(Get-ADOrganizationalUnit -Filter 'Name -like "Exempt"' -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential |
					Where-Object { $_.DistinguishedName -like "*$CBU*" }).DistinguishedName
			}
			
		}
		catch { $_ }
		
		$localComputerAdminGroup = "{0} Administrators" -f $adComputer.Name
		
		$exemptADGroup = try
		{
			if (!$global:Credential)
			{
				Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
			}
			else
			{
				Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
			}
			
		}
		catch
		{
			try
			{
				if (!$global:Credential)
				{
					New-ADGroup -Name $localComputerAdminGroup -GroupScope DomainLocal -Path $ExemptOU -ErrorAction Stop -Server $ComputerDomainName
					Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
				}
				else
				{
					
					New-ADGroup -Name $localComputerAdminGroup -GroupScope DomainLocal -Path $ExemptOU -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
					Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
				}
				
			}
			catch { $_ }
		}
		
		try
		{
			if (!$global:Credential)
			{
				$enableGPOGroup = Get-ADGroup -Identity 'Enable GPO - HKE Local Admin - Computer' -Server $ComputerDomainName -ErrorAction Stop
			}else
			{
				$enableGPOGroup = Get-ADGroup -Identity 'Enable GPO - HKE Local Admin - Computer' -Server $ComputerDomainName -ErrorAction Stop -Credential $global:Credential
			}
		
		try
			{
				if (!($enableGPOGroup | Get-ADGroupMember | Where-Object{$_.name -eq $adComputer.name}))
				{
					if (!$global:Credential)
					{
						$enableGPOGroup | Add-ADGroupMember -Server $ComputerDomainName -Members $adComputer -ErrorAction Stop
						
					}
					else
					{
						$enableGPOGroup | Add-ADGroupMember -Server $ComputerDomainName -Members $adComputer -ErrorAction Stop -Credential $global:Credential
					}
				}
					$("Added: {0} to `"{1}`"`n" -f $adComputer.name, $enableGPOGroup.name)	
			}
			catch { $_ }
		}
		catch { $_ }
		
		$addedExemptADGroupMember = if ($adUser | Get-Member | Where-Object{ $_.TypeName -eq "Microsoft.ActiveDirectory.Management.ADUser" })
		{
			
			try
		{
			if (!$global:Credential)
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
			else
			{
				$groupMemebrs = $exemptADGroup | Get-ADGroupMember -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
				try
				{
					if (!($groupMemebrs | Where-Object{ $_.SamAccountName -eq $adUser.SamAccountName }))
					{
						$exemptADGroup | Add-ADGroupMember -Members $adUser -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
						$exemptADGroup | Get-ADGroupMember -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
					}
					else { $groupMemebrs }
				}
				catch { $_ }
			}
			
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
			 $("Issue Adding: {0} to membership of `"{1}`"`n{2}" -f $adUser.Name, $exemptADGroup.Name, $addedExemptADGroupMember)
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
			if (!$global:Credential)
			{
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
			}
			else
			{
				Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
			}
			
		}
		catch
		{
			try
			{
				$ComputerDomainName = $domainTwo
				if (!$global:Credential)
				{
					Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName
				}
				else
				{
					Get-ADComputer -Identity $ComputerName -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
				}
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
			if (!$global:Credential)
			{
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
			}
			else
			{
				Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName -Credential $global:Credential
			}
		}
		catch
		{
			try
			{
				$UserDomainName = $domainTwo
				if (!$global:Credential)
				{
					Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName
				}
				else
				{
					Get-ADUser -Identity $UserName -ErrorAction Stop -Server $UserDomainName -Credential $global:Credential
				}
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
			if (!$global:Credential)
			{
				Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName
			}
			else
			{
				Get-ADGroup $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential
			}
		}
		catch { $_ }
		if ($exemptADGroup.Name)
		{
			try
			{
				if (!$global:Credential)
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
				else
				{
					if (Get-ADGroupMember $localComputerAdminGroup -ErrorAction Stop -Server $ComputerDomainName -Credential $global:Credential | Where-Object { $_.SamAccountName -eq $adUser.SamAccountName })
					{
						$exemptADGroup | Remove-ADGroupMember -Credential $global:Credential -Members $adUser -Confirm:$false -ErrorAction Stop
						$("Removed {0} from AD group `"{1}`"`n" -f $adUser.Name, $exemptADGroup.Name)
					}
					else
					{
						$("User {0} not found in AD group `"{1}`"`n" -f $adUser.Name, $exemptADGroup.Name)
					}
					
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

