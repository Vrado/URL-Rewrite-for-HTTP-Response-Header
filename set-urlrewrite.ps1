
function Set-urlrewrite
{
    <#
        
            Created by kkontek@kpmg.com | 04/2016

            .SYNOPSIS
            Installiert das IIS URL Rewrite Modul und erstellt Regeln um ungewollte Informationen im HTTP Header auszublenden.
       
            .DESCRIPTION
            Um im Penetration Test keine Auffälligkeit zu haben sollte dieses Skript die ungewollten Informationen im Header leer setzen.
            Das Skript läuft automatisch durch und installiert das URL Rewrite Modul. Falls das URL Rewrite Modul bereits installiert ist, wird dieser Schritt übersprungen.
            Mithilfe des URL Rewrite Moduls werden die Werte Server-Header, ASP-NET Header und X-Powered by Header mit einem leeren String belegt.

            Basisinformationen sind hier zu finden:
            https://blogs.msdn.microsoft.com/varunm/2013/04/23/remove-unwanted-http-response-headers/
            https://blogs.msdn.microsoft.com/david.wang/2006/03/29/silly-security-scans/

        
            .PARAMETER Site
            Definiert die dedizierte Website im IIS welche die Änderung betreffen soll.

            .EXAMPLE
            Set-urlrewrite -Site DefaultWebsite
        
            .NOTES
            v 1.0 - Initial Release mit URL Rewrite Silent Install und Anpassung der Rules auf Basis des Skriptes von Michael Held.  
            
            Upcoming in next Release:
            -Bulk URL Rewrite für mehrere Webseiten
            -Validitätsprüfung ob Webseite vorhanden 
            -Webseiten in Array speichern und auslesen

                 
        
        
    #>

    #Setzung des Website Parameters als zwingende Variable
    Param(
        [parameter(Mandatory = $true)]
        [String]
    $Site )

    
   
   
    <#---Silent Install URL Rewrite IIS Module ---#>

    #Mittels Registry Eintrag prüfen ob URL Rewrite bereits installiert ist
    $RewriteReg = Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite'
    if ($RewriteReg -eq $true)
    {
        #Falls URL Rewrite vorhanden ist wird der Installationsschrit übersprungen
        Write-Host -Object 'URL Rewrite IIS Module already installed. Skipping this Step!' -ForegroundColor Green
    }

    else
    {   
        #Falls URL Rewrite nicht installiert ist wird die Installationsdatei im relativen Pfad via msiexec silent installiert
        $scriptpath = Get-Location 
        Write-Host -Object 'Installing URL Rewrite. Please wait! ' -ForegroundColor Yellow
        msiexec.exe /i "$scriptpath\rewrite_2.0_rtw_x64.msi" /qn
        Start-Sleep -Seconds 30
    }
   

    #IIS Powershell Modul laden
    Import-Module -Name webadministration 
    
    #Ausgeben der Websites
    Get-ChildItem -Path IIS:\Sites\
    

    
    #erlaubte Server Variablen ergänzen
    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' 
    -Location $Site -Filter 'system.webServer/rewrite/allowedServerVariables' 
    -Name '.' 
    -Value @{
        name = 'RESPONSE_SERVER'
    }
    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $Site -Filter 'system.webServer/rewrite/allowedServerVariables' -Name '.' -Value @{
        name = 'RESPONSE_X-ASPNET-VERSION'
    }
    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $Site -Filter 'system.webServer/rewrite/allowedServerVariables' -Name '.' -Value @{
        name = 'RESPONSE_X-POWERED-BY'
    }
    
    #Outbound Regel für leeren Server-Header 
    Add-WebConfigurationProperty 
    -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  
    -Filter 'system.webServer/rewrite/outboundRules' 
    -Name '.' 
    -Value @{
        name = 'IIS-SERVER-Header'
    }
    Set-WebConfigurationProperty 
    -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  
    -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-SERVER-Header']/match" 
    -Name 'serverVariable' 
    -Value 'RESPONSE_SERVER'
    
    Set-WebConfigurationProperty 
    -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  
    -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-SERVER-Header']/match" 
    -Name 'pattern' 
    -Value '.*'

    Set-WebConfigurationProperty 
    -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  
    -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-SERVER-Header']/action" 
    -Name 'type' 
    -Value 'Rewrite'
    
    #Outbound Regel für leeren ASPNET-Header
    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter 'system.webServer/rewrite/outboundRules' -Name '.' -Value @{
        name = 'IIS-ASPNET-Header'
    }
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-ASPNET-Header']/match" -Name 'serverVariable' -Value 'RESPONSE_X-ASPNET-VERSION'
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-ASPNET-Header']/match" -Name 'pattern' -Value '.*'
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-ASPNET-Header']/action" -Name 'type' -Value 'Rewrite'
    
    #Outbound Regel für leeren Server-X-PoweredBy-Header
    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter 'system.webServer/rewrite/outboundRules' -Name '.' -Value @{
        name = 'IIS-PoweredBy-Header'
    }
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-PoweredBy-Header']/match" -Name 'serverVariable' -Value 'RESPONSE_X-POWERED-BY'
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-PoweredBy-Header']/match" -Name 'pattern' -Value '.*'
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$Site"  -Filter "system.webServer/rewrite/outboundRules/rule[@name='IIS-PoweredBy-Header']/action" -Name 'type' -Value 'Rewrite'

    Write-Host "All Done!" -ForegroundColor Green
}
#ausführen der function
Set-urlrewrite

