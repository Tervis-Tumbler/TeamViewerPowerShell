function Get-TeamViewerApiAuthorizationCode {
    param (
        $ClientId,
        $RedirectUri
    )
    $AuthorizationServer = "https://login.teamviewer.com/oauth2/authorize"
    $Uri = $AuthorizationServer + "?response_type=code&client_id=$ClientId&redirect_uri=$RedirectUri"
    start $Uri
    Read-Host "Enter TeamViewer authorization code"    
}

function Get-TeamViewerUserAccessToken {
    param (
        [Parameter(Mandatory)]$AuthorizationCode,
        [Parameter(Mandatory)]$ClientId,
        [Parameter(Mandatory)]$ClientSecret,
        $RedirectUri
    )
    $Uri = "https://webapi.teamviewer.com/api/v1/oauth2/token"
    $Body = "grant_type=authorization_code&code=$AuthorizationCode&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecret"
    Invoke-RestMethod -Method Post -Uri $Uri -ContentType application/x-www-form-urlencoded -Body $Body
}

function Update-TeamViewerUserAccessTokenFile {
    param (
        $TeamViewerAccessTokenFile = "~\TeamViewerUserAccessToken.xml",
        [Parameter(Mandatory)]$ClientId,
        [Parameter(Mandatory)]$ClientSecret
    )
    $EncryptedRefreshToken = (Import-Clixml -Path $TeamViewerAccessTokenFile).RefreshToken
    $RefreshToken = Get-ValueFromEncryptedString -String $EncryptedRefreshToken
    $Uri = "https://webapi.teamviewer.com/api/v1/oauth2/token"
    $Body = "grant_type=refresh_token&refresh_token=$RefreshToken&client_id=$ClientId&client_secret=$ClientSecret"
    $NewTeamViewerUserAccessToken = Invoke-RestMethod -Method Post -Uri $Uri -Body $Body -ContentType application/x-www-form-urlencoded
    $NewTeamViewerUserAccessToken | Export-TeamViewerUserAccessTokenToFile -Path $TeamViewerAccessTokenFile
}

function Export-TeamViewerUserAccessTokenToFile {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$access_token,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$token_type,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$expires_in,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$refresh_token,
        $Path = "~\TeamViewerUserAccessToken.xml"
    )
    process {
        $AccessToken = ConvertTo-SecureString -String $access_token -AsPlainText -Force | ConvertFrom-SecureString
        [DateTime]$ExpirationDate = (Get-Date).AddMinutes($expires_in)
        $RefreshToken = ConvertTo-SecureString -String $refresh_token -AsPlainText -Force | ConvertFrom-SecureString
        [PSCustomObject][Ordered]@{
            AccessToken = $AccessToken
            TokenType = $token_type.substring(0,1).toupper()+$token_type.substring(1).tolower()
            ExpirationDate = $ExpirationDate
            RefreshToken = $RefreshToken
        } | Export-Clixml -Path $Path -Force
    }
}

function Import-TeamViewerUserAccessTokenFromFile {
    param (
        $Path = "~\TeamViewerUserAccessToken.xml"
    )
    try {
        $UserAccessTokenObject = Import-Clixml -Path $Path
    } catch {
        throw "TeamViewer User Access Token file not found at $Path."
    }
    $CurrentDate = Get-Date
    if ($UserAccessTokenObject.ExpirationDate -lt $CurrentDate) {
        Update-TeamViewerUserAccessTokenFile -TeamViewerAccessTokenFile $Path
        $UserAccessTokenObject = Import-Clixml -Path $Path
    }
    [PSCustomObject][Ordered]@{
        UserAccessToken = Get-ValueFromEncryptedString -String $UserAccessTokenObject.AccessToken
        TokenType = $UserAccessTokenObject.TokenType
    }        
}

function Get-ValueFromEncryptedString {
    param (
        [Parameter(Mandatory)]$String
    )
    $SecureString = ConvertTo-SecureString -String $String 
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}
