Sandbox Setup Guide
Complete guide for setting up the VirtualBox sandbox environment for dynamic malware analysis.

Overview
The sandbox consists of two VMs on a host-only network:

REMnux — simulates internet services (InetSim + FakeDNS)
Windows VM — isolated execution environment
Prerequisites
VirtualBox 7.x installed on the XDR server
Host-only network adapter configured: 192.168.56.0/24
Ubuntu server (XDR host)
Minimum 8GB RAM, 100GB disk on host
Part 1: REMnux VM Setup
1.1 Download REMnux
# Download REMnux OVA
wget https://remnux.org/remnux-focal.ova

# Import into VirtualBox
VBoxManage import remnux-focal.ova \
    --vsys 0 --vmname "REMnux" \
    --vsys 0 --memory 2048 \
    --vsys 0 --cpus 2
1.2 Configure REMnux Network
# Add host-only adapter
VBoxManage modifyvm "REMnux" \
    --nic1 hostonly \
    --hostonlyadapter1 vboxnet0

# Set static IP (inside REMnux)
# Edit /etc/netplan/00-installer-config.yaml:
network:
  ethernets:
    eth0:
      addresses: [192.168.56.10/24]
      gateway4: 192.168.56.1
  version: 2
1.3 Configure InetSim
# Inside REMnux
sudo apt-get install inetsim

# Edit /etc/inetsim/inetsim.conf
sudo nano /etc/inetsim/inetsim.conf

# Key settings:
# service_bind_address 192.168.56.10
# dns_default_ip 192.168.56.10
# start_service dns
# start_service http
# start_service https
# start_service ftp
# start_service smtp

# Start InetSim
sudo systemctl start inetsim
sudo systemctl enable inetsim
1.4 Configure FakeDNS
# FakeDNS is included with InetSim
# Verify DNS simulation is working:
nslookup google.com 192.168.56.10
# Should return 192.168.56.10 for all domains
1.5 Start PCAP Capture
# REMnux captures all traffic from Windows VM
sudo tcpdump -i eth0 -w /captures/malware_$(date +%Y%m%d_%H%M%S).pcap &
Part 2: Windows VM Setup
2.1 Create Windows VM
# Create VM
VBoxManage createvm \
    --name "Windows_Sandbox" \
    --ostype Windows10_64 \
    --register

# Configure hardware
VBoxManage modifyvm "Windows_Sandbox" \
    --memory 4096 \
    --cpus 2 \
    --firmware efi \
    --tpm-type 2.0 \
    --graphicscontroller vmsvga \
    --vram 128

# Create disk
VBoxManage createmedium disk \
    --filename "C:/VMs/Windows_Sandbox/Windows_Sandbox.vdi" \
    --size 60000 \
    --format VDI

# Attach disk
VBoxManage storagectl "Windows_Sandbox" \
    --name "SATA Controller" \
    --add sata \
    --controller IntelAhci

VBoxManage storageattach "Windows_Sandbox" \
    --storagectl "SATA Controller" \
    --port 0 \
    --device 0 \
    --type hdd \
    --medium "C:/VMs/Windows_Sandbox/Windows_Sandbox.vdi"
2.2 Network Configuration
# Adapter 1: Host-only (for XDR server communication)
VBoxManage modifyvm "Windows_Sandbox" \
    --nic1 hostonly \
    --hostonlyadapter1 vboxnet0

# Adapter 2: Internal network pointing to REMnux
VBoxManage modifyvm "Windows_Sandbox" \
    --nic2 internal \
    --intnet2 malnet
Inside Windows, set static IP:

IP: 192.168.56.20
Subnet: 255.255.255.0
Gateway: 192.168.56.1
DNS: 192.168.56.10 (REMnux)
2.3 Install Required Tools
Inside Windows VM, install:

# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install tools
choco install -y python3
choco install -y wireshark
choco install -y procmon
choco install -y processhacker
2.4 Enable WinRM
# Run as Administrator in Windows VM
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Set WinRM password
$password = ConvertTo-SecureString "YourPassword123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("sandboxuser", $password)

# Test from XDR server
# python3 -c "import winrm; s = winrm.Session('192.168.56.20', auth=('sandboxuser', 'YourPassword123!')); r = s.run_cmd('ipconfig'); print(r.std_out)"
2.5 NAT Port Forwarding (XDR server access)
# From XDR server - allow access to Windows VM via host
VBoxManage modifyvm "Windows_Sandbox" \
    --natpf1 "winrm,tcp,,5985,,5985" \
    --natpf1 "rdp,tcp,,3389,,3389"
2.6 Take Clean Snapshot
# After Windows is fully configured and clean
VBoxManage snapshot "Windows_Sandbox" take "Clean_Base" \
    --description "Clean Windows installation with WinRM enabled"
Part 3: XDR Server Integration
3.1 Update main.py Configuration
# In main.py, set these sandbox variables:
SANDBOX_VM_NAME = "Windows_Sandbox"
SANDBOX_SNAPSHOT = "Clean_Base"
SANDBOX_IP = "192.168.56.20"
WINRM_USER = "sandboxuser"
WINRM_PASS = "YourPassword123!"
REMNUX_IP = "192.168.56.10"
PCAP_CAPTURE_PATH = "/captures/"
3.2 Sandbox Workflow
XDR Server receives suspicious file
    │
    ▼
Restore Windows VM to Clean_Base snapshot
    │
    ▼
Start REMnux PCAP capture
    │
    ▼
Copy suspicious file to Windows VM (WinRM/WinSCP)
    │
    ▼
Execute file via WinRM
    │
    ▼
Wait 60 seconds (configurable)
    │
    ▼
Stop PCAP capture
    │
    ▼
Copy PCAP to XDR server
    │
    ▼
Extract 39 features → Random Forest → Verdict
    │
    ▼
Restore VM to snapshot (clean state)
Part 4: Testing
Test InetSim
# From Windows VM
curl http://google.com
# Should return InetSim HTTP response

nslookup evil.com
# Should return 192.168.56.10
Test WinRM
import winrm
s = winrm.Session('192.168.56.20', auth=('sandboxuser', 'YourPassword123!'))
r = s.run_cmd('whoami')
print(r.std_out)
# Should print: windows_sandbox\sandboxuser
Test Full Pipeline
# Send an EICAR test file to the XDR server
curl -X POST http://localhost:8000/api/analyze \
    -F "file=@eicar.txt"
Troubleshooting
Problem	Solution
WinRM connection refused	Check firewall: netsh advfirewall firewall add rule name="WinRM" dir=in action=allow protocol=TCP localport=5985
InetSim not responding	sudo systemctl restart inetsim
VM snapshot restore fails	Check disk space on host: df -h
PCAP file empty	Verify tcpdump is running on REMnux before malware execution
Windows VM BSOD	Restore to Clean_Base snapshot, may indicate malware was too aggressive
