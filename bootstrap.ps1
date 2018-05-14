<powershell>
Start-Transcript -path "C:\Bootstrap.txt" -append

Dism /Online /Enable-Feature /FeatureName:IIS-ASPNET /All
Dism /Online /Enable-Feature /FeatureName:IIS-ASPNET45 /All
Dism /Online /Enable-Feature /FeatureName:IIS-CertProvider /All
Dism /Online /Enable-Feature /FeatureName:IIS-HttpRedirect /All
Dism /Online /Enable-Feature /FeatureName:IIS-BasicAuthentication /All
Dism /Online /Enable-Feature /FeatureName:IIS-WebSockets /All
Dism /Online /Enable-Feature /FeatureName:IIS-ApplicationInit /All
Dism /Online /Enable-Feature /FeatureName:IIS-CustomLogging /All
Dism /Online /Enable-Feature /FeatureName:IIS-ManagementService /All
Dism /Online /Enable-Feature /FeatureName:WCF-Services45 /All
Dism /Online /Enable-Feature /FeatureName:WCF-HTTP-Activation45 /All
Dism /Online /Enable-Feature /FeatureName:IIS-WindowsAuthentication /All

$tentacleDownloadPath = "https://octopus.com/downloads/latest/WindowsX64/OctopusTentacle"
$octopusServerUrl = $env:OCTOPUS_URL
$octopusApiKey = $env:OCTOPUS_API
$octopusServerThumbprint = $env:OCTOPUS_THUMBPRINT
$tentacleListenPort = 10933
$tentacleHomeDirectory = "C:\Octopus"
$tentacleAppDirectory = "C:\Octopus\Applications"
$tentacleConfigFile = "C:\Octopus\Tentacle\Tentacle.config"

$tentaclePath = "C:\Tools\Octopus.Tentacle.msi"

function Get-MyPublicIPAddress {
    # Get Ip Address of Machine
    Write-Host "Getting public IP address"
    $ipAddress = Invoke-RestMethod http://ipinfo.io/json | Select-Object -exp ip
    return $ipAddress
}

function Get-FileFromServer
{
  param (
    [string]$url,
    [string]$saveAs
  )

  Write-Host "Downloading $url to $saveAs"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $downloader = new-object System.Net.WebClient
  $downloader.DownloadFile($url, $saveAs)
}

function Install-Tentacle
{
  param (
     [Parameter(Mandatory=$True)]
     [string]$apiKey,
     [Parameter(Mandatory=$True)]
     [System.Uri]$octopusServerUrl
  )

  Write-Output "Beginning Tentacle installation"

  Write-Output "Downloading latest Octopus Tentacle MSI..."

  $tentaclePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(".\Tentacle.msi")
  if ((test-path $tentaclePath) -ne $true) {
    Get-FileFromServer $tentacleDownloadPath $tentaclePath
  }

  Write-Output "Installing MSI"
  $msiExitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList "/i Tentacle.msi /quiet" -Wait -Passthru).ExitCode
  Write-Output "Tentacle MSI installer returned exit code $msiExitCode"
  if ($msiExitCode -ne 0) {
    throw "Installation aborted"
  }

  Write-Output "Open port $tentacleListenPort on Windows Firewall"
  & netsh.exe firewall add portopening TCP $tentacleListenPort "Octopus Tentacle"
  if ($lastExitCode -ne 0) {
    throw "Installation failed when modifying firewall rules"
  }

  $ipAddress = Get-MyPublicIPAddress
  $ipAddress = $ipAddress.Trim()

  Write-Output "Public IP address: " + $ipAddress

  Write-Output "Configuring and registering Tentacle"

  Set-Location "${env:ProgramFiles}\Octopus Deploy\Tentacle"

  & .\tentacle.exe create-instance --instance "Tentacle" --config $tentacleConfigFile --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on create-instance"
  }
  & .\tentacle.exe configure --instance "Tentacle" --home $tentacleHomeDirectory --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on configure"
  }
  & .\tentacle.exe configure --instance "Tentacle" --app $tentacleAppDirectory --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on configure"
  }
  & .\tentacle.exe configure --instance "Tentacle" --port $tentacleListenPort --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on configure"
  }
  & .\tentacle.exe new-certificate --instance "Tentacle" --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on creating new certificate"
  }
  & .\tentacle.exe configure --instance "Tentacle" --trust $octopusServerThumbprint --console  | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on configure"
  }
  & .\tentacle.exe register-with --instance "Tentacle" --server $octopusServerUrl --role "Database-TerraForm" --role "Web-TerraForm" --environment "Dev" --environment "Test" --environment "Pre-Prod" --environment "Production" --environment "TearDown" --name $env:COMPUTERNAME --publicHostName $ipAddress --apiKey $apiKey --comms-style TentaclePassive --force --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on register-with"
  }

  & .\tentacle.exe service --instance "Tentacle" --install --start --console | Write-Host
  if ($lastExitCode -ne 0) {
    throw "Installation failed on service install"
  }

  Write-Output "Tentacle commands complete"
}

# Install tentacle now ... 
Install-Tentacle -apikey $octopusApiKey -octopusServerUrl $octopusServerUrl

</powershell>