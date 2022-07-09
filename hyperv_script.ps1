Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",
    [Parameter(Mandatory=$True)]
    [string]
    $Message,
    [Parameter(Mandatory=$False)]
    [string]
    $logfile
    )
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $date = (Get-Date).toString("yyyy-MM-dd")
    $content = "[$Stamp] [$Level] $Message"
    If($logfile) {
        $logfile+="_"+$date
        $logfile+=".log"
        Add-Content $logfile -Value $content
     }
    Else {
        Write-Output $content
    }
}
 function Get-CurrentLineNumber {
    $MyInvocation.ScriptLineNumber
}
$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$InstallerLogFileName="$ScriptDirectory\InstallerRemoteLog"
$List = Import-CSV "$env:temp\\parameters.csv" -UseCulture
ForEach($VM in $List)
{
$Name = $($VM.vmname)
$IPaddress = $($VM.ipaddr)
$Mask = $($VM.subnet)
$GateW = $($VM.gateway)
$DNS = $($VM.dns)
$TemplatePath = $($VM.templatepath)
$SourcePath = $($VM.vhdsourcepath)
$DestinationPath = $($VM.vhddestinationpath)
$RawMemory = "$($VM.memory)"+"GB"
$Memory = [int64]$RawMemory.Replace('GB','') * 1GB
$cpu = "$($VM.cpu)"
$rawdisksize = "$($VM.disksize)"+"GB"
$disksize = [int64]$rawdisksize.Replace('GB','') * 1GB
$vswitch = "$($VM.vswitchname)"
$AssetName = "$($VM.assetname)"
$vhd = "$AssetName", "vhdx" -join '.'
# Create directory to copy the vm's images
if (Test-Path -Path $DestinationPath) {
    $DestinationPath = $DestinationPath+"New"
    New-Item $DestinationPath -ItemType Directory -Force
    Write-Log "INFO" "[$(Get-CurrentLineNumber)] $DestinationPath directory created  successfully" "$InstallerLogFileName"
} else {
    New-Item $DestinationPath -ItemType Directory -Force
    Write-Log "INFO" "[$(Get-CurrentLineNumber)] $DestinationPath directory created  successfully" "$InstallerLogFileName"
}
try{
	$REPORT = Compare-VM -Path $TemplatePath -Copy  -VhdSourcePath  $SourcePath -VhdDestinationPath $DestinationPath -GenerateNewId
	if ( $? -ne $true ) {
        Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to repare vm information" "$InstallerLogFileName"
        exit 1
    }
    if ($REPORT.Incompatibilities -ne $null) {
        $REPORT.Incompatibilities[0].Source | Disconnect-VMNetworkAdapter
        $SWITCH = Get-VMSwitch -SwitchType External
        if ($SWITCH -eq $null) {
            Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Network Switch information does not found." "$InstallerLogFileName"
            exit 1
        }
        $REPORT.Incompatibilities[0].Source | Connect-VMNetworkAdapter -SwitchName $SWITCH[0].Name
    }
# Import vm's
    $VM_INFO = Import-VM -CompatibilityReport $REPORT
    Write-Log "INFO" "[$(Get-CurrentLineNumber)] VM Imported SUccessfully." "$InstallerLogFileName"
}
catch{
    Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to import VM." "$InstallerLogFileName"
}
# Rename vm's name
try{
    Rename-VM -VM $VM_INFO -NewName $Name
    if ( $? -ne $true ) {
        Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to rename new vm." "$InstallerLogFileName"
        exit 1
    }
    else{
        Write-Log "INFO" "[$(Get-CurrentLineNumber)] VM Renamed SUccessfully." "$InstallerLogFileName"
    }
}
catch{
    Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to rename new vm." "$InstallerLogFileName"	
}
# Set vm's memory,cpu
try{
    Set-VM -VMName $Name -ProcessorCount $cpu -MemoryStartupBytes $Memory -StaticMemory
	if ( $? -ne $true ) {
        Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to set new vm." "$InstallerLogFileName"
        exit 1
    }
    else{
        Write-Log "INFO" "[$(Get-CurrentLineNumber)] VM Set with CPU, Memory Successfully." "$InstallerLogFileName"
    }
}
catch{
    Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to set new vm." "$InstallerLogFileName"
}

# Set virtual hard disk size	
try
{
	Resize-VHD -Path $DestinationPath\\$vhd -SizeBytes $disksize
	if ( $? -ne $true ) {
        Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to resize hard disk." "$InstallerLogFileName"
        exit 1
    }
    else{
        Write-Log "INFO" "[$(Get-CurrentLineNumber)] Hard DIask resized Successfully." "$InstallerLogFileName"
    }
}
catch{
	Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to resize hard disk." "$InstallerLogFileName"
}

# Start virtual machines
try{
    Start-VM -Name $Name
    if ( $? -ne $true ) {
        Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to start the VM." "$InstallerLogFileName"
        exit 1
    }
    else{
        Write-Log "INFO" "[$(Get-CurrentLineNumber)] VM Started Successfully." "$InstallerLogFileName"
    }
}
catch{
	Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to start the VM." "$InstallerLogFileName"
}
Start-Sleep -Seconds 180

# Assign static ip of vm's
try
{
	$VMManServ =  Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
	$vm = Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $Name }
	$vmSettings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' } 
	$nwAdapters = $vmSettings.GetRelated('Msvm_SyntheticEthernetPortSettingData') 
	$ipstuff = $nwAdapters.getrelated('Msvm_GuestNetworkAdapterConfiguration')
	$ipstuff.DHCPEnabled = $false
	$ipstuff.DNSServers = $DNS
	$ipstuff.IPAddresses = $IPaddress
	$ipstuff.Subnets = $Mask
	$ipstuff.DefaultGateways = $GateW
	$setIP = $VMManServ.SetGuestNetworkAdapterConfiguration($VM, $ipstuff.GetText(1))
	Write-Host $setIP
	Write-Log "INFO" "[$(Get-CurrentLineNumber)] Static IP assigned to the VM successfully." "$InstallerLogFileName"
}
catch{
	Write-Log "ERROR" "[$(Get-CurrentLineNumber)] Failed to assign static IP to the VM." "$InstallerLogFileName"
}
}