from bcc import BPF

# --- 1. BODYGUARD'IN TALİMATLARI (C Kodu) ---
program_kodu = """
#include <uapi/linux/ptrace.h>

int dosya_acilisini_yakala(struct pt_regs *ctx) {
    // Adım 1: Boş bir kağıt hazırla (Maksimum 256 karakterlik yer ayırıyoruz)
    char dosya_ismi[256];

    // Adım 2: MAŞA ile veriyi çek (bpf_probe_read_user_str)
    // openat(dfd, filename, flags) fonksiyonunda dosya ismi 2. argümandır.
    // PT_REGS_PARM2(ctx) -> Bize 2. argümanın adresini verir.
    bpf_probe_read_user_str(&dosya_ismi, sizeof(dosya_ismi), (void *)PT_REGS_PARM2(ctx));

    // Adım 3: İspiyonla (Sadece dosya ismini ekrana bas)
    // Not: "Acilan" yerine "Open" yazıyoruz Türkçe karakter sorunu olmasın.
    bpf_trace_printk("Hedef: %s\\n", dosya_ismi);

    return 0;
}
"""

# --- 2. BODYGUARD'I KAPININ ÖNÜNE KOYMA (Python Kodu) ---
# BPF nesnesini oluştur
b = BPF(text=program_kodu)

# Doğru kapıyı bul (openat sistem çağrısı)
# Kernel versiyonuna göre ismi değişebilir, get_syscall_fnname işimizi garantiye alır.
kapi_ismi = b.get_syscall_fnname("openat")

# Bodyguard'ı kapıya dik (Kprobe ile hook atıyoruz)
b.attach_kprobe(event=kapi_ismi, fn_name="dosya_acilisini_yakala")

print(f"Ajan devrede! '{kapi_ismi}' izleniyor... (Durdurmak için Ctrl+C)")

# --- 3. RAPORLARI OKU ---
try:
    # Gelen logları sürekli ekrana bas
    b.trace_print()
except KeyboardInterrupt:
    print("\nAjan görevi bıraktı.")
