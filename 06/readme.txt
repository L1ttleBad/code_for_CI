开始测试
cd 06-stp
make
sudo python four_node_ring.py/six_node_net.py
 > xterm b1 b2 b3 b4 / b1 b2 b3 b4 b5 b6
 > xterm b1
 b? # ./stp
 b1 # pkill -SIGTERM stp

输出结果
./dump_output.sh / ./dump_output_6.sh


