`xdp_ddos_protect` fork com alterações pra rodar no robô Unitree Go2


### compila o código xdp

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp_ddos_protection.c -o xdp_ddos_protection.o
```

### attach na interface de rede

```bash
sudo ip link set dev <interface> xdpgeneric obj xdp_ddos_protection.o sec xdp
```

### compila e pina os mapas

```bash
gcc pin.c -o pin $(pkg-config --cflags --libs libbpf) -lbpf
```

```bash
sudo ./pin
```

### compila e roda o monitor

```bash
gcc monitor.c -o monitor $(pkg-config --cflags --libs libbpf) -lbpf
```

```bash
sudo ./monitor
```

### no host, 