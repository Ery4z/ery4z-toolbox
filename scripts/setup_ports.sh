ufw allow 22
ufw allow 80
ufw allow 443

# Zabbix agent 
ufw allow 10050/tcp

# Docker Swarm
ufw allow 2377/tcp
ufw allow 7946
ufw allow 4789/udp
