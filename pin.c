#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/bpf.h>

static int try_pin_map(int fd, struct bpf_map_info *info) {
    const char *pin_path = NULL;

    if (
        info->type == BPF_MAP_TYPE_HASH &&
        info->key_size == 4 &&
        info->value_size == 16 &&
        info->max_entries == 1024
    ) {
        pin_path = "/sys/fs/bpf/rate_limit_map";
    }

    else if (
        info->type == BPF_MAP_TYPE_HASH &&
        info->key_size == 4 &&
        info->value_size == 1 &&
        info->max_entries == 1024
    ) {
        pin_path = "/sys/fs/bpf/blacklist_map";
    }

    else {
        return 0;
    }

    if (bpf_obj_pin(fd, pin_path) == 0) {
        printf("map pinado em %s\n", pin_path);
        return 1;
    }

    if (errno == EEXIST) {
        printf("map ja pinado em %s\n", pin_path);
        return 1;
    }

    perror("bpf_obj_pin");
    return -1;
}

int main(void) {
    __u32 id = 0;

    int rate_found = 0;
    int blacklist_found = 0;

    while (bpf_map_get_next_id(id, &id) == 0) {

        int fd = bpf_map_get_fd_by_id(id);

        if (fd < 0)
            continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);

        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {

            if (
                info.type == BPF_MAP_TYPE_HASH &&
                info.key_size == 4 &&
                info.value_size == 16 &&
                info.max_entries == 1024
            ) {
                if (try_pin_map(fd, &info) > 0)
                    rate_found = 1;
            }

            else if (
                info.type == BPF_MAP_TYPE_HASH &&
                info.key_size == 4 &&
                info.value_size == 1 &&
                info.max_entries == 1024
            ) {
                if (try_pin_map(fd, &info) > 0)
                    blacklist_found = 1;
            }
        }

        close(fd);
    }

    if (!rate_found)
        printf("rate_limit_map nao encontrado\n");

    if (!blacklist_found)
        printf("blacklist_map nao encontrado\n");

    return 0;
}