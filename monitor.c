typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_IPS 1024
#define RATE_LIMIT 3

struct rate_limit_entry {
    unsigned long long last_update;
    unsigned int packet_count;
};

int main()
{
    int rate_fd;
    int blacklist_fd;
    unsigned int last_count[MAX_IPS] = {0};

    rate_fd = bpf_obj_get("/sys/fs/bpf/rate_limit_map");

    if (rate_fd < 0) {
        perror("Erro ao abrir rate_limit_map");
        return 1;
    }

    blacklist_fd = bpf_obj_get("/sys/fs/bpf/blacklist_map");

    if (blacklist_fd < 0) {
        perror("Erro ao abrir blacklist_map");
        return 1;
    }

    printf("Mapas abertos com sucesso!\n");

    __u32 key;
    __u32 next_key;

    while (1) {
        int result;

        result = bpf_map_get_next_key(
            rate_fd,
            NULL,
            &next_key
        );

        while (result == 0) {
            struct rate_limit_entry value;

            if (
                bpf_map_lookup_elem(
                    rate_fd,
                    &next_key,
                    &value
                ) == 0
            ) {

                int index = next_key % MAX_IPS;
                struct in_addr ip_addr;
                ip_addr.s_addr = next_key;

                if (value.packet_count != last_count[index]) {
                    if (value.packet_count <= RATE_LIMIT) {
                        printf(
                            "PING de %s -> %u pacotes\n",
                            inet_ntoa(ip_addr),
                            value.packet_count
                        );
                    }                

                    else if (value.packet_count == RATE_LIMIT + 1) {
                        printf(
                            "PING de %s -> %u pacotes. [STRIKE] limite excedido\n",
                            inet_ntoa(ip_addr),
                            value.packet_count
                        );                    
                    }

                    else {
                        printf (
                            "%s [BLACKLISTED] \n",
                            inet_ntoa(ip_addr)
                        );  
                    }

                    last_count[index] = value.packet_count;
                }                
            }

            key = next_key;

            result = bpf_map_get_next_key(
                rate_fd,
                &key,
                &next_key
            );
        }

        usleep(1000);
    }

    return 0;
}