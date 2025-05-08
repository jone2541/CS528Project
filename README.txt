#To collect
#sudo ./project.py --mode collect -i <interface> --label <0,1>
#To Train
#sudo ./project.py --mode train –-contamination 0.3
#sudo ./project.py --mode train -i enp0s3 --contamination 0.3
#To Detect
#sudo ./project.py --mode detect -i <interface> 


To generate 'good' DNS requests, use dns_generate_0.py from the attacker.
#chmod 755 project.py
#sudo ./dns_generate_0.py

#useful DNS Commands
cat /var/cache/bind/dump.db | grep ns.dnslabattacker.net
sudo rndc dumpdb -cache
sudo rndc flush
dig @192.168.15.4 example.edu +norecurse