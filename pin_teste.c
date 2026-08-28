typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    __u32 id = 0;

    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);

        if (fd < 0)
            continue;

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
        }

        close(fd);
    }

    return 0;
}