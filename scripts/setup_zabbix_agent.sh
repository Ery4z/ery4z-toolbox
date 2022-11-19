echo "Please enter the name of the host:"
read

wget https://repo.zabbix.com/zabbix/6.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.2-4%2Bubuntu20.04_all.deb
sudo dpkg -i zabbix-release_6.2-4+ubuntu20.04_all.deb
sudo apt update



sudo apt install zabbix-agent
cp zabbix_agentd.conf.original zabbix_agentd.conf
sed -i 's|Zabbix Server|'"$REPLY"'|g' /etc/zabbix/zabbix_agentd.conf
sed -i 's|127.0.0.1|45.92.110.208|g' /etc/zabbix/zabbix_agentd.conf

sudo ufw allow 10050

sudo systemctl restart zabbix-agent

echo "Please modify the hostname in /etc/zabbix/zabbix_agentd.conf"
