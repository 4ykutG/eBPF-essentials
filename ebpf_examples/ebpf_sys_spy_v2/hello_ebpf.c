# include <linux/bpf.h>
# include <bpf/bpf_helpers.h>

// Bu fonksiyon sistemde her yeni program çalıştığında tetiklenir ve kullanıcıya bilgi verir.
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
	char msg[] = "Yeni bir program baslatildi!\n";

	// bpf_trace_printk, kernel debug loguna (/sys/kernel/tracing/trace_pipe) yazar.
	bpf_trace_printk(msg, sizeof(msg));

	return 0;
}

char _license[] SEC("license") = "GPL";
