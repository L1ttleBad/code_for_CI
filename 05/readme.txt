开始测试
cd 05-switching
make
sudo python three_nodes_bw.py
 > xterm h1 h2 h3 s1
 > xterm h1
 s1 # ./switch

 
测试网络负载
h1为client
 h2 # iperf -s
 h3 # iperf -s 
 h1 # iperf -c 10.0.0.2 -t 30
 h1 # iperf -c 10.0.0.3 -t 30



