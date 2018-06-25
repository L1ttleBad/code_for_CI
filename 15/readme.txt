编译
make clean 
make

运行
sudo python tcp_topo.py
>> xterm h1 h2


h1 >> ./tcp_stack server 10001
h2 >> ./tcp_stack client 10.0.0.1 10001
