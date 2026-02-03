from bcc import BPF
import os

# --- 1. MENÜ VE SEÇİM KISMI (AYNI) ---
def menu_goster():
    os.system('clear')
    print("=== INTERAKTIF DOSYA AJANI (TRACEPOINT VERSIYON) ===")
    print("Hangi uygulamalari izlemek istersin? (Virgulle ayirabilirsin)")
    print("1. Firefox")
    print("2. Steam")
    print("3. Signal")
    print("4. VirtualBox")
    print("5. Code (VSCode)")
    print("6. Hepsi (Filtresiz)")
    
    secim = input("\nSecimin (Ornek: 1,3): ")
    return secim

secimler = menu_goster()
hedef_uygulamalar = []

if "1" in secimler: hedef_uygulamalar.append("firefox")
if "2" in secimler: hedef_uygulamalar.append("steam")
if "3" in secimler: hedef_uygulamalar.append("signal")
if "4" in secimler: hedef_uygulamalar.append("VirtualBox")
if "5" in secimler: hedef_uygulamalar.append("code")

if not hedef_uygulamalar or "6" in secimler:
    print("\n[!] Tüm sistem izleniyor (Filtre YOK)...")
    hedef_uygulamalar = []
else:
    print(f"\n[+] Hedefler: {', '.join(hedef_uygulamalar)}")

# --- 2. C KODU (TRACEPOINT ILE DEGISTI) ---
# Kprobe yerine TRACEPOINT_PROBE macrosunu kullaniyoruz.
# Bu macro bize "args" adinda sihirli bir degisken verir.
# args->filename diyerek dogrudan dosya ismine ulasiriz. Register aramaya son!

program_kodu = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// syscalls:sys_enter_openat noktasina kanca atiyoruz
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char dosya_ismi[256];
    char kimlik[16];

    // 1. Dosya ismini dogrudan args yapisindan cekiyoruz
    // args->filename: Kernel'in bize verdigi garanti adres.
    bpf_probe_read_user_str(dosya_ismi, sizeof(dosya_ismi), args->filename);

    // 2. Kimligi al
    bpf_get_current_comm(&kimlik, sizeof(kimlik));

    // 3. Ispiyonla
    bpf_trace_printk("%s|%s\\n", kimlik, dosya_ismi);

    return 0;
}
"""

# --- 3. BAĞLANTI (TRACEPOINT OTOMATIK BAGLANIR) ---
# Tracepoint kullanirken attach_kprobe yapmamiza gerek yok.
# TRACEPOINT_PROBE macrosu otomatik aktif olur.
b = BPF(text=program_kodu)

print(f"\n[OK] Tracepoint 'sys_enter_openat' dinleniyor... Basladik!\n")
print(f"{'UYGULAMA':<16} | {'ACILAN DOSYA'}")
print("-" * 60)

# --- 4. FILTRELEME (AYNI) ---
while True:
    try:
        ham_veri = b.trace_readline()
        satir = ham_veri.decode('utf-8', 'ignore')
        
        if ":" in satir:
            mesaj_kismi = satir.split(":")[-1].strip()
            
            if "|" in mesaj_kismi:
                uygulama, dosya = mesaj_kismi.split("|", 1)
                
                goster = False
                if not hedef_uygulamalar:
                    goster = True
                else:
                    for hedef in hedef_uygulamalar:
                        if hedef in uygulama.lower():
                            goster = True
                            break
                
                if goster:
                    # Bos dosya isimlerini (bazen olur) ekrana basma
                    if len(dosya) > 1:
                        print(f"{uygulama:<16} | {dosya}")

    except KeyboardInterrupt:
        print("\n\n[!] Takip sonlandırıldı.")
        exit()
    except Exception as e:
        continue
