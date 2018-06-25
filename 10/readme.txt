编译
make clean 
make

运行
sudo python nat_topo.py
>> xterm n1 h1 h2

n1 >> ./nat
h2 >> python -m SimpleHTTPServer
h1 >> wget http://159.226.39.123:8000
