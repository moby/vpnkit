$ethernet = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name 30D48B34-7D27-4B0B-AAAF-BBBED334DD59
$ethernet.SetValue("ElementName", "Docker VPN proxy")

$ports = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name 0B95756A-9985-48AD-9470-78E060895BE7
$ports.SetValue("ElementName", "Docker port forwarding")
