function Invoke-TeamViewerApiLogin {
    param (
        
    )
}

function Get-TeamViewerApiAuthorizationCode {
    param (
        $ClientId,
        $RedirectUri
    )
    $AuthorizationServer = "https://login.teamviewer.com/oauth2/authorize"
    $Uri = $AuthorizationServer + "?response_type=code&client_id=$ClientId&redirect_uri=$RedirectUri"
    start $Uri
    $AuthorizationCode = Read-Host "Enter TeamViewer authorization code"
    $AuthorizationCode
}

function Get-TeamViewerApiAccessToken {
    param (
        [Parameter(Mandatory)]$AuthorizationCode
    )
    $Uri = "https://webapi.teamviewer.com/api/v1/oauth2/token"
    $code = $AuthorizationCode
    $ClientId = (Get-PasswordstateCredential -PasswordID 4127 -AsPlainText).UserName
    $ClientSecret = (Get-PasswordstateCredential -PasswordID 4127 -AsPlainText).Password
    $RedirectUri = "https://somenonexistentoauthclient.com/oauth"
    $Body = "grant_type=authorization_code&code=$code&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecret"
    Invoke-RestMethod -Method Post -Uri $Uri -ContentType application/x-www-form-urlencoded -Body $Body
}

function Export-TeamViewerApiTokenFile {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$access_token,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$token_type,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$expires_in,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$refresh_token
    )
    process {
        $AccessToken = 
        [PSCustomObject][Ordered]@{
            AccessToken = $access_token
        }
    }
}
