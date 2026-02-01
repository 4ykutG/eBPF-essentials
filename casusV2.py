from bcc import BPF

# 1. KERNEL TARAFI
# trace_printk yerine bpf_trace_printk daha sağlamdır.
# Ayrıca hangi programın çalıştığını anlamak için 'bpf_get_current_comm' ekleyelim.
kernel_kod = """
#include <linux/sched.h>

int dedektif_fonksiyon(void *ctx) {
    char comm[16];
    // Çalışan programın ismini (ls, bash, python vb.) alıyoruz
    bpf_get_current_comm(&comm, sizeof(comm));
    
    bpf_trace_printk("YAKALANDI: %s calistirildi!\\n", comm);
    return 0;
}
"""

# 2. KÖPRÜ
b = BPF(text=kernel_kod)

# 3. KANCAYI ATMA (Daha garanti bir yöntemle)
# Bazı sistemlerde 'execve' direkt çalışmaz, '__x64_sys_execve' gerekebilir. 
# get_syscall_fnname bunu otomatik çözer.
fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=fnname, fn_name="dedektif_fonksiyon")

print(f"[{fnname}] izleniyor... Bir seyler calistirmayi dene!")

# 4. OKUMA
# trace_print bazen takılabilir, o yüzden manuel okuma döngüsü yapalım
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\\nCasus emekli oldu.")
    exit()
