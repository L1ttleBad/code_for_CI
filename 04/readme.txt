开始测试转发
cd 04-broadcast
make clean 
make
sudo python three_nodes_bw.py
 > xterm h1 h2 h3 b1
 b1 # ./hub
 之后再h1h2h3中ping其它节点即可
 如 h1 # ping 10.0.0.2 -c 4
 
测试网络负载
h1为client
 h2 # iperf -s
 h3 # iperf -s 
 h1 # iperf -c 10.0.0.2 -t 30
 h1 # iperf -c 10.0.0.3 -t 30

h1为server
 h1 # iperf -s
 h2 # iperf -c 10.0.0.1 -t 30
 h3 # iperf -c 10.0.0.1 -t 30

观察环路转发
cd 04-broadcast-circular-edition
make clean 
make
sudo python three_nodes_bw.py
 > xterm b1 b2 b3 h1
 b1 # ./hub
 b2 # ./hub
 b3 # ./hub
 h1 # ping -c 1 10.0.0.2