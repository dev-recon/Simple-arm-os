/* src/parser.c */
#include "shell.h"

token_t* tokenize(const char* line) {
    token_t* head = NULL;
    token_t* tail = NULL;
    const char* p = line;
    char buffer[MAX_LINE];
    int buf_pos = 0;
    
    while (*p) {
        /* Ignorer les espaces */
        while (*p && isspace(*p)) {
            p++;
        }
        
        if (!*p) break;
        
        buf_pos = 0;
        token_type_t type = TOKEN_WORD;
        
        /* Caracteres speciaux */
        if (*p == '|') {
            if (*(p+1) == '|') {
                type = TOKEN_OR;
                p += 2;
            } else {
                type = TOKEN_PIPE;
                p++;
            }
        } else if (*p == '&') {
            if (*(p+1) == '&') {
                type = TOKEN_AND;
                p += 2;
            } else {
                type = TOKEN_BACKGROUND;
                p++;
            }
        } else if (*p == '<') {
            type = TOKEN_REDIRECT_IN;
            p++;
        } else if (*p == '>') {
            if (*(p+1) == '>') {
                type = TOKEN_REDIRECT_APPEND;
                p += 2;
            } else {
                type = TOKEN_REDIRECT_OUT;
                p++;
            }
        } else if (*p == ';') {
            type = TOKEN_SEMICOLON;
            p++;
        } else {
            /* Mot normal */
            int in_quotes = 0;
            char quote_char = 0;
            
            while (*p && (in_quotes || (!isspace(*p) && 
                   strchr("|&<>;", *p) == NULL))) {
                if ((*p == '"' || *p == '\'') && !in_quotes) {
                    in_quotes = 1;
                    quote_char = *p;
                    p++;
                    continue;
                } else if (*p == quote_char && in_quotes) {
                    in_quotes = 0;
                    quote_char = 0;
                    p++;
                    continue;
                } else if (*p == '\\' && !in_quotes) {
                    p++;
                    if (*p) {
                        buffer[buf_pos++] = *p++;
                    }
                    continue;
                }
                
                buffer[buf_pos++] = *p++;
                
                if (buf_pos >= MAX_LINE - 1) {
                    break;
                }
            }
        }
        
        buffer[buf_pos] = '\0';
        
        /* Creer le token */
        token_t* token = malloc(sizeof(token_t));
        if (!token) {
            perror("malloc");
            free_tokens(head);
            return NULL;
        }
        
        token->type = type;
        token->value = (type == TOKEN_WORD) ? strdup(buffer) : NULL;
        token->next = NULL;
        
        if (!head) {
            head = tail = token;
        } else {
            tail->next = token;
            tail = token;
        }
    }
    
    return head;
}

command_line_t* parse_command_line(token_t* tokens) {
    command_line_t* cmdline = malloc(sizeof(command_line_t));
    if (!cmdline) {
        perror("malloc");
        return NULL;
    }
    
    cmdline->pipelines = malloc(MAX_ARGS * sizeof(pipeline_t*));
    cmdline->pipeline_count = 0;
    
    token_t* current = tokens;
    pipeline_t* pipeline = NULL;
    
    while (current) {
        if (current->type == TOKEN_SEMICOLON || 
            current->type == TOKEN_AND || 
            current->type == TOKEN_OR) {
            
            if (pipeline) {
                cmdline->pipelines[cmdline->pipeline_count] = pipeline;
                cmdline->separators[cmdline->pipeline_count] = current->type;
                cmdline->pipeline_count++;
                pipeline = NULL;
            }
            current = current->next;
        } else {
            if (!pipeline) {
                pipeline = parse_pipeline(&current);
                if (!pipeline) {
                    free_command_line(cmdline);
                    return NULL;
                }
            } else {
                current = current->next;
            }
        }
    }
    
    if (pipeline) {
        cmdline->pipelines[cmdline->pipeline_count] = pipeline;
        cmdline->pipeline_count++;
    }
    
    return cmdline;
}

pipeline_t* parse_pipeline(token_t** tokens) {
    pipeline_t* pipeline = malloc(sizeof(pipeline_t));
    if (!pipeline) {
        perror("malloc");
        return NULL;
    }
    
    pipeline->commands = malloc(MAX_ARGS * sizeof(simple_cmd_t*));
    pipeline->cmd_count = 0;
    pipeline->background = 0;
    
    token_t* current = *tokens;
    simple_cmd_t* cmd = NULL;
    
    while (current && current->type != TOKEN_SEMICOLON && 
           current->type != TOKEN_AND && current->type != TOKEN_OR) {
        
        if (current->type == TOKEN_PIPE) {
            if (cmd) {
                pipeline->commands[pipeline->cmd_count++] = cmd;
                cmd = NULL;
            }
            current = current->next;
        } else if (current->type == TOKEN_BACKGROUND) {
            pipeline->background = 1;
            current = current->next;
        } else {
            if (!cmd) {
                cmd = parse_simple_command(&current);
                if (!cmd) {
                    free_pipeline(pipeline);
                    return NULL;
                }
            } else {
                current = current->next;
            }
        }
    }
    
    if (cmd) {
        pipeline->commands[pipeline->cmd_count++] = cmd;
    }
    
    *tokens = current;
    return pipeline;
}

simple_cmd_t* parse_simple_command(token_t** tokens) {
    simple_cmd_t* cmd = malloc(sizeof(simple_cmd_t));
    if (!cmd) {
        perror("malloc");
        return NULL;
    }
    
    cmd->args = malloc(MAX_ARGS * sizeof(char*));
    cmd->argc = 0;
    cmd->redirects = NULL;
    
    token_t* current = *tokens;
    
    while (current && current->type != TOKEN_PIPE && 
           current->type != TOKEN_SEMICOLON &&
           current->type != TOKEN_AND && current->type != TOKEN_OR &&
           current->type != TOKEN_BACKGROUND) {
        
        if (current->type == TOKEN_WORD) {
            /* Expansion des variables */
            char* expanded = expand_variables(current->value);
            cmd->args[cmd->argc++] = expanded;
            current = current->next;
        } else if (current->type == TOKEN_REDIRECT_IN ||
                   current->type == TOKEN_REDIRECT_OUT ||
                   current->type == TOKEN_REDIRECT_APPEND) {
            
            redirect_t* redir = malloc(sizeof(redirect_t));
            redir->type = current->type;
            redir->fd = (current->type == TOKEN_REDIRECT_IN) ? 0 : 1;
            
            current = current->next;
            if (current && current->type == TOKEN_WORD) {
                redir->filename = strdup(current->value);
                redir->next = cmd->redirects;
                cmd->redirects = redir;
                current = current->next;
            } else {
                free(redir);
                fprintf(stderr, "Erreur de syntaxe: fichier attendu apres redirection\n");
                free_simple_command(cmd);
                return NULL;
            }
        } else {
            current = current->next;
        }
    }
    
    cmd->args[cmd->argc] = NULL;
    *tokens = current;
    
    return cmd;
}

void free_tokens(token_t* tokens) {
    token_t* current = tokens;
    while (current) {
        token_t* next = current->next;
        free(current->value);
        free(current);
        current = next;
    }
}

void free_command_line(command_line_t* cmdline) {
    int i;
    if (!cmdline) return;
    
    for (i = 0; i < cmdline->pipeline_count; i++) {
        free_pipeline(cmdline->pipelines[i]);
    }
    free(cmdline->pipelines);
    free(cmdline);
}

void free_pipeline(pipeline_t* pipeline) {
    int i;
    if (!pipeline) return;
    
    for (i = 0; i < pipeline->cmd_count; i++) {
        free_simple_command(pipeline->commands[i]);
    }
    free(pipeline->commands);
    free(pipeline);
}

void free_simple_command(simple_cmd_t* cmd) {
    int i;
    if (!cmd) return;
    
    for (i = 0; i < cmd->argc; i++) {
        free(cmd->args[i]);
    }
    free(cmd->args);
    
    redirect_t* redir = cmd->redirects;
    while (redir) {
        redirect_t* next = redir->next;
        free(redir->filename);
        free(redir);
        redir = next;
    }
    
    free(cmd);
}