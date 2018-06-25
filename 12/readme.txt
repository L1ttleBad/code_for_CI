编译
make clean 
make

运行
sudo python topo.py
>> xterm r1 r2 r3 r4 h1

r* >> ./mospfd
等待一段时间，待打印出来的路由条目稳定后，便可进行ping和traceroute操作

h1 >> ping 10.0.6.22 -c 4
h1 >> traceroute 10.0.6.22
