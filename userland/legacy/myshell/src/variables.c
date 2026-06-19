/* src/variables.c */
#include "shell.h"

void init_shell_variables(int argc, char** argv) {
    char buffer[32];
    int i;
    
    /* Variables speciales */
    set_shell_variable("0", argv[0]); /* $0 */
    
    snprintf(buffer, sizeof(buffer), "%d", argc - 1);
    set_shell_variable("#", buffer); /* $# */
    
    snprintf(buffer, sizeof(buffer), "%d", getpid());
    set_shell_variable("$", buffer); /* $$ */
    
    set_shell_variable("?", "0"); /* $? */
    
    /* Arguments positionnels */
    for (i = 1; i < argc && i < 10; i++) {
        snprintf(buffer, sizeof(buffer), "%d", i);
        set_shell_variable(buffer, argv[i]);
    }
    
    /* Variables d'environnement importantes */
    if (!getenv("PS1")) {
        setenv("PS1", "myshell$ ", 1);
    }
    
    if (!getenv("PS2")) {
        setenv("PS2", "> ", 1);
    }
    
    if (!getenv("PATH")) {
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
    }
    
    /* Mettre a jour le prompt */
    update_prompt();
}

char* expand_variables(const char* str) {
    if (!str) return NULL;
    
    char* result = malloc(MAX_LINE);
    if (!result) return NULL;
    
    const char* p = str;
    char* out = result;
    
    while (*p && out - result < MAX_LINE - 1) {
        if (*p == '$' && *(p+1)) {
            p++;
            
            if (*p == '{') {
                /* ${variable} */
                p++;
                char varname[256];
                char* vp = varname;
                
                while (*p && *p != '}' && vp - varname < 255) {
                    *vp++ = *p++;
                }
                *vp = '\0';
                
                if (*p == '}') p++;
                
                char* value = get_shell_variable(varname);
                if (!value) value = getenv(varname);
                if (value) {
                    while (*value && out - result < MAX_LINE - 1) {
                        *out++ = *value++;
                    }
                }
            } else if (isalnum(*p) || *p == '_') {
                /* $variable */
                char varname[256];
                char* vp = varname;
                
                while (*p && (isalnum(*p) || *p == '_') && vp - varname < 255) {
                    *vp++ = *p++;
                }
                *vp = '\0';
                
                char* value = get_shell_variable(varname);
                if (!value) value = getenv(varname);
                if (value) {
                    while (*value && out - result < MAX_LINE - 1) {
                        *out++ = *value++;
                    }
                }
            } else if (isdigit(*p)) {
                /* Variables positionnelles $1, $2, etc. */
                char varname[2] = {*p, '\0'};
                char* value = get_shell_variable(varname);
                if (value) {
                    while (*value && out - result < MAX_LINE - 1) {
                        *out++ = *value++;
                    }
                }
                p++;
            } else {
                /* Caracteres speciaux $?, $$, $#, etc. */
                char varname[2] = {*p, '\0'};
                char* value = get_shell_variable(varname);
                if (value) {
                    while (*value && out - result < MAX_LINE - 1) {
                        *out++ = *value++;
                    }
                }
                p++;
            }
        } else if (*p == '~' && (p == str || *(p-1) == ' ' || *(p-1) == ':')) {
            /* Expansion du tilde */
            char* expanded = expand_tilde(p);
            char* exp_p = expanded;
            
            /* Avancer p apres le tilde */
            p++;
            while (*p && *p != '/' && *p != ' ' && *p != ':') {
                p++;
            }
            
            /* Copier le resultat de l'expansion */
            while (*exp_p && out - result < MAX_LINE - 1) {
                *out++ = *exp_p++;
            }
            
            free(expanded);
        } else {
            *out++ = *p++;
        }
    }
    
    *out = '\0';
    return result;
}

char* expand_tilde(const char* str) {
    if (!str || str[0] != '~') {
        return strdup(str);
    }
    
    char* result = malloc(MAX_PATH);
    if (!result) return NULL;
    
    const char* p = str + 1;
    char* home = NULL;
    
    if (*p == '\0' || *p == '/') {
        /* ~/... ou ~ seul */
        home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) {
                home = pw->pw_dir;
            }
        }
    } else {
        /* ~user/... */
        char username[256];
        char* up = username;
        
        while (*p && *p != '/' && up - username < 255) {
            *up++ = *p++;
        }
        *up = '\0';
        
        struct passwd* pw = getpwnam(username);
        if (pw) {
            home = pw->pw_dir;
        }
    }
    
    if (home) {
        snprintf(result, MAX_PATH, "%s%s", home, p);
    } else {
        strncpy(result, str, MAX_PATH - 1);
        result[MAX_PATH - 1] = '\0';
    }
    
    return result;
}

void set_shell_variable(const char* name, const char* value) {
    shell_var_t* var = shell_state.variables;
    
    /* Chercher si la variable existe deja */
    while (var) {
        if (strcmp(var->name, name) == 0) {
            free(var->value);
            var->value = strdup(value);
            return;
        }
        var = var->next;
    }
    
    /* Creer une nouvelle variable */
    var = malloc(sizeof(shell_var_t));
    if (!var) return;
    
    var->name = strdup(name);
    var->value = strdup(value);
    var->next = shell_state.variables;
    shell_state.variables = var;
}

char* get_shell_variable(const char* name) {
    shell_var_t* var = shell_state.variables;
    
    while (var) {
        if (strcmp(var->name, name) == 0) {
            return var->value;
        }
        var = var->next;
    }
    
    return NULL;
}

void unset_shell_variable(const char* name) {
    shell_var_t** var_ptr = &shell_state.variables;
    
    while (*var_ptr) {
        if (strcmp((*var_ptr)->name, name) == 0) {
            shell_var_t* to_remove = *var_ptr;
            *var_ptr = to_remove->next;
            free(to_remove->name);
            free(to_remove->value);
            free(to_remove);
            return;
        }
        var_ptr = &(*var_ptr)->next;
    }
}