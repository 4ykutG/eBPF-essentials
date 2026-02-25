#include <stdio.h>
#include <stdlib.h>

int main ()
{
    // Kullanicidan 2 adet sayi aliniz 
    // Kullanicidan isminin bas harfini aliniz
    // Kullanicidan alinan bu bilgileri 1. sayim 2. sayim ve ismimin bas harfi diye ekrana bastiriniz.

    int sayi1;
    int sayi2;
    char basharf;

    printf("bir sayi giriniz: ");
    scanf("%d", &sayi1);

    printf("ikinci sayiyi giriniz: ");
    scanf("%d", &sayi2);

    printf("isminizin bas harfini girin: ");
    scanf(" %c", &basharf);

    printf("kullanicinin girdigi 1. sayi:%d 2. sayi: %d isminin bas harfi %c",sayi1,sayi2,basharf);

    return 0;
}