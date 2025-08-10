/* src/prompt.c */
#include "shell.h"

void update_prompt(void) {
    char* ps1 = getenv("PS1");
    if (!ps1) {
        ps1 = "myshell$ ";
    }
    
    free(shell_state.prompt);
    shell_state.prompt = expand_prompt(ps1);
}

char* expand_prompt(const char* ps1) {
    char* result = malloc(MAX_LINE);
    if (!result) return strdup("$ ");
    
    const char* p = ps1;
    char* out = result;
    
    while (*p && out - result < MAX_LINE - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++; /* Sauter le backslash */
            
            switch (*p) {
                case 'u': /* Nom d'utilisateur */
                {
                    char* user = getenv("USER");
                    if (!user) {
                        struct passwd* pw = getpwuid(getuid());
                        if (pw) user = pw->pw_name;
                    }
                    if (user) {
                        while (*user && out - result < MAX_LINE - 1) {
                            *out++ = *user++;
                        }
                    }
                    break;
                }
                
                case 'h': /* Nom d'hote (partie courte) */
                {
                    char hostname[256];
                    if (gethostname(hostname, sizeof(hostname)) == 0) {
                        char* dot = strchr(hostname, '.');
                        if (dot) *dot = '\0';
                        char* h = hostname;
                        while (*h && out - result < MAX_LINE - 1) {
                            *out++ = *h++;
                        }
                    }
                    break;
                }
                
                case 'H': /* Nom d'hote complet */
                {
                    char hostname[256];
                    if (gethostname(hostname, sizeof(hostname)) == 0) {
                        char* h = hostname;
                        while (*h && out - result < MAX_LINE - 1) {
                            *out++ = *h++;
                        }
                    }
                    break;
                }
                
                case 'w': /* Repertoire de travail complet */
                {
                    char* cwd = shell_state.cwd;
                    char* home = getenv("HOME");
                    
                    if (home && strncmp(cwd, home, strlen(home)) == 0) {
                        *out++ = '~';
                        cwd += strlen(home);
                    }
                    
                    while (*cwd && out - result < MAX_LINE - 1) {
                        *out++ = *cwd++;
                    }
                    break;
                }
                
                case 'W': /* Nom du repertoire de travail (basename) */
                {
                    char* cwd = shell_state.cwd;
                    char* basename = strrchr(cwd, '/');
                    if (basename) {
                        basename++;
                    } else {
                        basename = cwd;
                    }
                    
                    /* Cas special pour le home */
                    char* home = getenv("HOME");
                    if (home && strcmp(cwd, home) == 0) {
                        *out++ = '~';
                    } else {
                        while (*basename && out - result < MAX_LINE - 1) {
                            *out++ = *basename++;
                        }
                    }
                    break;
                }
                
                case '$': /* $ si utilisateur normal, # si root */
                    *out++ = (getuid() == 0) ? '#' : '$';
                    break;
                    
                case 't': /* Heure au format HH:MM:SS */
                {
                    time_t now = time(NULL);
                    struct tm* tm_info = localtime(&now);
                    char time_str[16];
                    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
                    char* t = time_str;
                    while (*t && out - result < MAX_LINE - 1) {
                        *out++ = *t++;
                    }
                    break;
                }
                
                case 'd': /* Date au format Jeu 23 Mai */
                {
                    time_t now = time(NULL);
                    struct tm* tm_info = localtime(&now);
                    char date_str[32];
                    strftime(date_str, sizeof(date_str), "%a %d %b", tm_info);
                    char* d = date_str;
                    while (*d && out - result < MAX_LINE - 1) {
                        *out++ = *d++;
                    }
                    break;
                }
                
                case 'n': /* Newline */
                    *out++ = '\n';
                    break;
                    
                case 'r': /* Carriage return */
                    *out++ = '\r';
                    break;
                    
                case '\\': /* Backslash litteral */
                    *out++ = '\\';
                    break;
                    
                case '!': /* Numero de commande dans l'historique */
                {
                    char hist_num[16];
                    snprintf(hist_num, sizeof(hist_num), "%d", shell_state.history_count + 1);
                    char* h = hist_num;
                    while (*h && out - result < MAX_LINE - 1) {
                        *out++ = *h++;
                    }
                    break;
                }
                
                case '?': /* Code de sortie de la derniere commande */
                {
                    char exit_code[16];
                    snprintf(exit_code, sizeof(exit_code), "%d", shell_state.last_exit_status);
                    char* e = exit_code;
                    while (*e && out - result < MAX_LINE - 1) {
                        *out++ = *e++;
                    }
                    break;
                }
                
                default:
                    /* Caractere non reconnu, le copier tel quel */
                    *out++ = '\\';
                    if (out - result < MAX_LINE - 1) {
                        *out++ = *p;
                    }
                    break;
            }
            p++;
        } else {
            *out++ = *p++;
        }
    }
    
    *out = '\0';
    return result;
}