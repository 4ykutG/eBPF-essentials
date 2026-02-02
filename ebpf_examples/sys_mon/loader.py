from bcc import BPF

# 1. monitor.c dosyasını oku
b = BPF(src_file="monitor.c")

# 2. Fonksiyonu execve tracepoint'ine bağla
# Not: BCC'de bu isimleri vermek çok daha kolaydır.
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="monitor_calistir")

print("--- Kanca Atıldı! Terminali izle, ls veya whoami yazınca buraya düşecek ---")

# 3. Mesajları ekrana bas
b.trace_print()
