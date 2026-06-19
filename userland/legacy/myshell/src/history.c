/* src/history.c */
#include "shell.h"

void add_to_history(const char* line) {
    if (!line || strlen(line) == 0) {
        return;
    }
    
    /* eviter les doublons consecutifs */
    if (shell_state.history_count > 0 && 
        strcmp(shell_state.history[shell_state.history_count - 1], line) == 0) {
        return;
    }
    
    /* Si l'historique est plein, decaler */
    if (shell_state.history_count >= MAX_HISTORY) {
        free(shell_state.history[0]);
        
        int i;
        for (i = 0; i < MAX_HISTORY - 1; i++) {
            shell_state.history[i] = shell_state.history[i + 1];
        }
        shell_state.history_count = MAX_HISTORY - 1;
    }
    
    /* Ajouter la nouvelle ligne */
    shell_state.history[shell_state.history_count] = strdup(line);
    shell_state.history_count++;
    shell_state.history_index = shell_state.history_count;
}

char* get_history_line(int index) {
    if (index < 0 || index >= shell_state.history_count) {
        return NULL;
    }
    
    return shell_state.history[index];
}

void save_history(const char* filename) {
    char* home = getenv("HOME");
    char filepath[MAX_PATH];
    
    if (home) {
        snprintf(filepath, sizeof(filepath), "%s/%s", home, filename);
    } else {
        strncpy(filepath, filename, sizeof(filepath) - 1);
        filepath[sizeof(filepath) - 1] = '\0';
    }
    
    FILE* file = fopen(filepath, "w");
    if (!file) {
        return; /* Pas d'erreur si on ne peut pas sauvegarder */
    }
    
    int i;
    for (i = 0; i < shell_state.history_count; i++) {
        fprintf(file, "%s\n", shell_state.history[i]);
    }
    
    fclose(file);
}

void load_history(const char* filename) {
    char* home = getenv("HOME");
    char filepath[MAX_PATH];
    char line[MAX_LINE];
    
    if (home) {
        snprintf(filepath, sizeof(filepath), "%s/%s", home, filename);
    } else {
        strncpy(filepath, filename, sizeof(filepath) - 1);
        filepath[sizeof(filepath) - 1] = '\0';
    }
    
    FILE* file = fopen(filepath, "r");
    if (!file) {
        return; /* Pas d'erreur si le fichier n'existe pas */
    }
    
    while (fgets(line, sizeof(line), file)) {
        /* Enlever le newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        /* Ajouter a l'historique sans verification de doublon */
        if (shell_state.history_count < MAX_HISTORY) {
            shell_state.history[shell_state.history_count] = strdup(line);
            shell_state.history_count++;
        } else {
            break; /* Historique plein */
        }
    }
    
    shell_state.history_index = shell_state.history_count;
    fclose(file);
}