#include <stdio.h>

int main() {
    char *p1 = malloc(10000);
    const char* path = " Path ";

    printf("p1 = 0x%08X, path = 0x%08X\n", p1, path);

    for( int i = 0 ; i < 26; i++)
    {
        p1[i] = 'A' + i;
    }
    p1[26] = '\0';

    printf("p1 content = $%s$, path content = $%s$\n", p1, path);

    char *p2 = malloc(200);
    
    printf("p2 = %p\n", p2);
    
    free(p1);
    
    char *p3 = malloc(50);  // Devrait réutiliser l'espace de p1
    printf("p3 = %p\n", p3);
    
    free(p2);
    free(p3);
    
    return 0;
}

