sudo systemctl stop docker.service
sudo systemctl stop docker.socket

sudo mkdir -p /home/docker
sudo sed  -e '/ExecStart=/s/$/ -g /home/docker/'

sudo rsync -aqxP /var/lib/docker/ /home/docker

sudo systemctl daemon-reload
sudo systemctl start docker

ps aux | grep -i docker | grep -v grep
