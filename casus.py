from bcc import BPF

# 1. Kernel tarafı (C Kodu)
# bu kod parçası direkt çekirdeğin içinde çalışacak kısımdır.
kernel_kod = """
int dedektif_fonksiyon(void *ctx) {
	bpf_trace_printk("Reis sistemde birisi yeni bir uygulama çalıştırdı ayık ol!!!\\n");
	return 0;
}
"""

# 2. Köprü kuralım
# C Kodumuzu alıp Kernel'a yükleyecek olan kısım
b = BPF(text=kernel_kod)

# 3. Hook Atma kısmı
# 'execve' syscall'u yeni bir program başlanırken tetiklenir.
# bizde bu syscall başladığında bizim 'dedektif fonksiyonu çalıştır' diyoruz
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="dedektif_fonksiyon")

# 4. Sonuçları okuma
print("casus su an sistemi izliyor, durdurmak için ctrl + c")
try:
	#kernel'dan gelen mesajları sürekli oku ve ekrana bas
	b.trace_print()
except KeyboardInterrupt:
	exit()
