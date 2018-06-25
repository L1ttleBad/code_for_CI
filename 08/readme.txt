开始测试
cd 08-router
make clean 
make
sudo python router_topo.py/3router_topo.py
 > xterm r1 h1 / r1 r2 r3 h1

 r* # ./router
 h1 # ping host_ip / ping router_ip / traceroute host_ip     //please use corresponding ip to replace the *_ip


