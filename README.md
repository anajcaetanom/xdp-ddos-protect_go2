`xdp_ddos_protect` fork com alterações pra rodar no robô Unitree Go2


### Compila o código xdp

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp_ddos_protection.c -o xdp_ddos_protection.o
```

### Attach na interface de rede

```bash
sudo ip link set dev <interface> xdpgeneric obj xdp_ddos_protection.o sec xdp
```

### Compila e pina os mapas

```bash
gcc pin.c -o pin $(pkg-config --cflags --libs libbpf) -lbpf
```

```bash
sudo ./pin
```

### Compila e roda o monitor

```bash
gcc monitor.c -o monitor $(pkg-config --cflags --libs libbpf) -lbpf
```

```bash
sudo ./monitor
```

### Pinga o robô no mínimo 5 vezes

Saída esperada:

```bash
:~/xdp-ddos-protect_go2$ sudo ./monitor 
Mapas abertos com sucesso!
PING de 192.168.122.1 -> 1 pacotes
PING de 192.168.122.1 -> 2 pacotes
PING de 192.168.122.1 -> 3 pacotes
PING de 192.168.122.1 -> 4 pacotes. [STRIKE] limite excedido
192.168.122.1 [BLACKLISTED] 
```