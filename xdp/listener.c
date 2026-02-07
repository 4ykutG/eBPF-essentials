// reader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main() {
    // Pinlediğimiz dosya yolu
    const char *map_path = "/sys/fs/bpf/my_stats/drop_map";
    int map_fd;
    __u32 key = 0;
    __u64 value;

    // Dosyayı 'file descriptor' olarak açıyoruz
    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("Map dosyasi acilamadi");
        return 1;
    }

    printf("8.8.8.8 Dropper Monitor Basladi...\n");

    while (1) {
        // Map'ten veriyi oku (Key 0 olan array elemanı)
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            printf("\rEngellenen Paket Sayisi: %llu", value);
            fflush(stdout);
        }
        sleep(1);
    }

    close(map_fd);
    return 0;
}
