编译
gcc -o ip ip.c

运行
./ip a b
其中 a用(0:基本前缀树匹配， 1：多bit前缀树匹配)
b用(1: 1bit 2: 2bits 3: 3bits 4: 4bits )
替代

要修改匹配次数请修改ip.c 18行的 MATCH_TIMES的值
要查看匹配的结果可以使用debug版本，去掉响应注释
要验证是否正确请去掉332开始的区块注释