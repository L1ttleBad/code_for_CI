进入本目录下
make clean 
make
sudo python topo.py
xterm h1 h2 h3

在h2和h3中，开启worker
./client

在h1中，开启master
./server

！！！请不要把上面的操作顺序弄反，否则会导致连接不上