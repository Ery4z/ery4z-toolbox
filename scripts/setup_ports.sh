sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443

# Zabbix agent 
sudo ufw allow 10050/tcp

# Docker Swarm
sudo ufw allow 2377/tcp
sudo ufw allow 7946
sudo ufw allow 4789/udp
