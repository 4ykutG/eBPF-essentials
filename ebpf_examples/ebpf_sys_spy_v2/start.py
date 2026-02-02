from bcc import BPF

# Kernel kodunu yukarıdaki C kodundan alıyoruz
program = """
int hello(void *ctx) {
    bpf_trace_printk("Merhaba eBPF Dunyasi!\\n");
    return 0;
}
"""

# Programı execve sistem çağrısına bağlıyoruz
b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello")

print("eBPF programı çalışıyor... Çıkmak için Ctrl+C. Logları görmek için başka bir terminal aç.")
b.trace_print()
