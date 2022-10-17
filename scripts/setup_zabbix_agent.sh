echo "Please enter the name of the host:"
read -p $HOSTNAME

wget https://repo.zabbix.com/zabbix/6.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.2-2%2Bubuntu18.04_all.deb
sudo dpkg -i zabbix-release_6.2-2+ubuntu18.04_all.deb
sudo apt update



sudo apt install zabbix-agent

sed -i 's|HOSTNAMEPLACEHOLDER|'"$HOSTNAME"'|g' zabbix_agentd.conf
sudo cp zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf
sudo mkdir /etc/zabbix/zabbix_agentd.conf.d
sudo systemctl restart zabbix-agent

echo "Please modify the hostname in /etc/zabbix/zabbix_agentd.conf"
