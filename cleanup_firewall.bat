@echo off
echo Cleaning up Downpour DDoS block rules that may be blocking legitimate traffic...
echo This requires Administrator privileges.
echo.

netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_34_149_66_163"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_34_149_66_163_out"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_160_79_104_10"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_160_79_104_10_out"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_35_190_46_17"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_35_190_46_17_out"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_23_15_253_120"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_23_15_253_120_out"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_35_223_238_178"
netsh advfirewall firewall delete rule name="Downpour_DDoS_Block_35_223_238_178_out"

echo.
echo Also removing any Downpour emergency block rules...
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_BLOCK"
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_BLOCK_IN"
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_ALLOW_DNS"
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_ALLOW_HTTPS"
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_ALLOW_HTTP"
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_ALLOW_QUIC"
netsh advfirewall firewall delete rule name="DOWNPOUR_EMERGENCY_ALLOW_LAN"

echo.
echo Also removing VPN kill switch rules...
netsh advfirewall firewall delete rule name="Downpour_VPN_KillSwitch_BlockAll"
netsh advfirewall firewall delete rule name="Downpour_VPN_KillSwitch_Allow_DNS"
netsh advfirewall firewall delete rule name="Downpour_VPN_KillSwitch_Allow_HTTPS"
netsh advfirewall firewall delete rule name="Downpour_VPN_KillSwitch_Allow_HTTP"
netsh advfirewall firewall delete rule name="Downpour_VPN_KillSwitch_Allow_QUIC"
netsh advfirewall firewall delete rule name="Downpour_VPN_KillSwitch_Allow_LAN"

echo.
echo Also removing Downpour KS rules...
netsh advfirewall firewall delete rule name="Downpour_KS_Allow_DNS"
netsh advfirewall firewall delete rule name="Downpour_KS_Allow_HTTPS"
netsh advfirewall firewall delete rule name="Downpour_KS_Allow_HTTP"
netsh advfirewall firewall delete rule name="Downpour_KS_Allow_QUIC"
netsh advfirewall firewall delete rule name="Downpour_KS_Allow_LAN"

echo.
echo Done! Please restart Claude and test.
pause