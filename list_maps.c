#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
    __u32 id = 0;

    while (bpf_map_get_next_id(id, &id) == 0) {

        int fd = bpf_map_get_fd_by_id(id);

        if (fd < 0) {
            printf(
                "falha ao abrir map id=%u: errno=%d (%s)\n",
                id,
                errno,
                strerror(errno)
            );
            continue;
        }

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);

        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {

            printf(
                "id=%u name='%s' type=%u key=%u value=%u max=%u\n",
                info.id,
                info.name,
                info.type,
                info.key_size,
                info.value_size,
                info.max_entries
            );

        } else {

            printf(
                "falha ao obter info do map id=%u: errno=%d (%s)\n",
                id,
                errno,
                strerror(errno)
            );
        }

        close(fd);
    }

    printf(
        "fim da enumeracao: errno=%d (%s)\n",
        errno,
        strerror(errno)
    );

    return 0;
}