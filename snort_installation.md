# Snort Installation on Kali Linux

## Step 1: Update and Upgrade Kali
```bash
sudo apt update && sudo apt upgrade -y
## step 2: install snort 
sudo apt install snort -y


During installation, I configured:

Snort interface: enp0s3

Home network range: 192.168.1.0/24

## step3: verify installation 
snort -V

## Step 4: Test Snort in NIDS mode 
sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf
