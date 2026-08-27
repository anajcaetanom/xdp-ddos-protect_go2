#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static int pin_map(const char *map_name, const char *pin_path) {
    __u32 id = 0;

    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);

        if (fd < 0)
            continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);

        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            if (strcmp(info.name, map_name) == 0) {

                if (bpf_obj_pin(fd, pin_path) == 0) {
                    printf("%s pinado em %s\n", map_name, pin_path);
                    close(fd);
                    return 0;
                }

                if (errno == EEXIST) {
                    printf("%s ja esta pinado em %s\n", map_name, pin_path);
                    close(fd);
                    return 0;
                }

                perror("bpf_obj_pin");
                close(fd);
                return -1;
            }
        }

        close(fd);
    }

    printf("mapa %s nao encontrado\n", map_name);
    return -1;
}

int main(void) {
    int ret = 0;

    if (pin_map(
        "rate_limit_map",
        "/sys/fs/bpf/rate_limit_map"
    ) < 0)
        ret = 1;

    if (pin_map(
        "blacklist_map",
        "/sys/fs/bpf/blacklist_map"
    ) < 0)
        ret = 1;

    return ret;
}