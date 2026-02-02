# include <linux/bpf.h> // eBPF dünyasının anahtar headerı
# include <bpf/bpf_helpers.h> // Kernelın bize verdiği yardım fonksiyonlarını içeren header

/*
SEC: "kamerayı nereye takıyoruz?"
yeni bir program çalıştırıldığında (execve) syscall u çalıştığında tetiklenecek
*/

SEC("tracepoint/syscalls/sys_enter_execve")
int monitor_calistir(void *ctx) {

	// 1. PID'yi saklamak için bir kutu hazırlayalım (32 bitlik pozitif tam sayı)
	unsigned int pid;

	/*
	2. kernel'daki robotu çağırıyoruz: "kim bu ?"
	bpf_get_current_pid_tgid() bize 64 bitlik bir sayı verir
	onun üst 32 bitini alıp pid kutusuna atıyoruz.
	*/

	pid = bpf_get_current_pid_tgid() >> 32;

	/*
	3. yakaladığımız PID'yi günlüğe yazalım.
	%u pozitif tamsayı (unsigned geleceğini söyler)
	bu adımda bir hata aldık pid sonuçta bir değişken ve dışarıdan manipüle edilerek 
	bellek taşması zafiyetlerine sebep olabilir
	bunu engellemek içi kodu bu halinden

	bpf_trace_printk("yakaladım!!! programı çalıştıran PID: %u\n", pid);

	*/

	// Mesajı önce bir değişkene atayalım ki boyutu net olsun
	char fmt[] = "Kanka yakaladim! PID: %u\n";
	bpf_trace_printk(fmt, sizeof(fmt), pid);
	// Bu hale çevirdik 

	// 4. kernel'a işim bitti, her şey yolunda (0) diyoruz
	return 0;

}

// olmazsa olmaz özgür yazılım lisansı
char _license[] SEC("license") = "GPL";

