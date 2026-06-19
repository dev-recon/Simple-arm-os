/* src/rcfiles.c */
#include "shell.h"

void load_rc_files(void) {
    /* Charger le fichier RC global */
    execute_rc_file("/etc/myshellrc");
    
    /* Charger le fichier RC utilisateur */
    char* home = getenv("HOME");
    if (home) {
        char rcfile_path[MAX_PATH];
        snprintf(rcfile_path, sizeof(rcfile_path), "%s/.myshellrc", home);
        execute_rc_file(rcfile_path);
    }
}

void execute_rc_file(const char* filename) {
    FILE* file;
    char line[MAX_LINE];
    command_line_t* cmdline;
    token_t* tokens;
    
    file = fopen(filename, "r");
    if (!file) {
        return; /* Pas d'erreur si le fichier n'existe pas */
    }
    
    while (fgets(line, sizeof(line), file)) {
        /* Enlever le newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        /* Ignorer les lignes vides et les commentaires */
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }
        
        /* Tokeniser */
        tokens = tokenize(line);
        if (!tokens) {
            continue;
        }
        
        /* Parser */
        cmdline = parse_command_line(tokens);
        if (!cmdline) {
            free_tokens(tokens);
            continue;
        }
        
        /* Executer */
        execute_command_line(cmdline);
        
        /* Nettoyer */
        free_command_line(cmdline);
        free_tokens(tokens);
    }
    
    fclose(file);
}