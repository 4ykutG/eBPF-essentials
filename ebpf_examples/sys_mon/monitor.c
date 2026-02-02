// BCC arka planda gerekli headerları eklediği için 
// manuel #include yapmamıza gerek kalmıyor.

int monitor_calistir(void *ctx) {
    u32 pid;

    /* bpf_get_current_pid_tgid() fonksiyonu bize 64 bitlik veri döner.
       Üst 32 bit gerçek PID (Process ID) değeridir. */
    pid = bpf_get_current_pid_tgid() >> 32;

    /* bpf_trace_printk mesajımızı kernel loglarına yazar.
       BCC'deki loader.py bu mesajları oradan okuyup bize gösterecek. */
    bpf_trace_printk("Kanka yakaladim! PID: %d\\n", pid);

    return 0;
}
