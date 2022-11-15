function Get-ResourceToken($resource = "https://graph.microsoft.com") {
    $resource = "?resource=$resource/"
    $url = $env:IDENTITY_ENDPOINT + $resource
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER)
    $Headers.Add("Metadata", "True")

    try {
        # Log "Fetching Access Token from $url"
        $Response = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers
        $script:access_token = $Response.access_token

    }	
    catch {
        # Log "Error with call"
        $StatusCode = $_.Exception.Response.StatusCode.value
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
    
        Log "Request Failed with Status: $StatusCode, Message: $responseBody"
    }

    return $script:access_token
}

function Notify($message) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "token=$($script:PushoverAppSecret)&user=$($script:PushoverUserSecret)&message=$message"
    # Log $body
    # Log $script:PushoverAppSecret
    # Log $script:PushoverUserSecret
	
    $response = Invoke-RestMethod 'https://api.pushover.net/1/messages.json' -Method 'POST' -Headers $headers -Body $body | Out-Null
    $response | ConvertTo-Json
}

function Check-Expiration($enddate, $app, $secretType) {
    $expiresIn = (New-TimeSpan -Start (Get-Date) -End $enddate).days

    if (@(1, 2, 3, 4, 5, 10, 15, 30, 60, 90).contains($expiresIn) ) {
        $message = "$($app.displayname) has a $secretType expiring in $expiresIn days"
        Notify $message
    }

    if ($expiresIn -le 0 ) {
        $message = "$($app.displayname) has a $secretType that already expired"
        Notify $message
    }
}

function Log($message) {
    if ($env:POWERSHELL_DISTRIBUTION_CHANNEL -eq 'AzureAutomation') {
        Write-Output $message
        Write-Host $message
    }
    else {
        Write-Output $message
        Write-Host $message
    }
}


if ($env:POWERSHELL_DISTRIBUTION_CHANNEL -eq 'AzureAutomation') {

    $script:PushoverAppSecret = Get-AutomationVariable -Name "PushoverAppSecret"
    $script:PushoverUserSecret = Get-AutomationVariable -Name "PushoverUserSecret"
}
else {
   
    $script:PushoverAppSecret = $env:PushoverAppSecret
    $script:PushoverUserSecret = $env:PushoverUserSecret
}



$token = Get-ResourceToken
try {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $token")
    $data = Invoke-RestMethod 'https://graph.microsoft.com/v1.0/applications?$count=true' -Method 'GET' -Headers $headers
}
catch {
    Write-Error "Error getting app list from graph API"
}

$apps = $data.value
$parsedData = $apps | % {
    $app = $_

    $certs = $app.keyCredentials
    $appCerts = $certs | % {
        $cert = $_
        $thumbprint = $cert.customKeyIdentifier
        $enddate = Get-Date $cert.enddatetime
        
        Log "`tCert $thumbprint expires on $enddate"
        Check-Expiration $enddate $app "Cert"

        @{
            thumbprint = $thumbprint
            enddate    = $enddate
        }
    }
    
    $secrets = $app.passwordCredentials

    $appSecrets = $secrets | % {
        $secret = $_
        $enddate = Get-Date $secret.enddatetime
        Log "`tSecret $($secret.keyid) expires on $enddate"
        Check-Expiration $enddate $app "Secret"
        
        @{
            secretId = $secret.keyid
            enddate  = $enddate
        }
    }


    @{
        appName = $app.displayname
        appId   = $app.appid
        certs   = $appCerts
        secrets = $appSecrets
    }
}
