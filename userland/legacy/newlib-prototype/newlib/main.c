/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/legacy/newlib-prototype/newlib/main.c
 * Layer: Userland / program
 * Description: ArmOS userspace program or support module.
 */

// userland/programs/hello/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Hello from Newlib userland!\n");
    
    // Test malloc
    char* buffer = malloc(256);
    if (buffer) {
        strcpy(buffer, "Dynamic allocation works!");
        printf("Allocated: %s\n", buffer);
        free(buffer);
    }
    
    // Test fichier
    FILE* f = fopen("/test_newlib.txt", "w");
    if (f) {
        fprintf(f, "Test from newlib: %d\n", 42);
        fclose(f);
        printf("File written successfully\n");
    }
    
    return 0;
}