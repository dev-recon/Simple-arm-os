/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/sed.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct sed_command {
    const char* pattern;
    const char* replacement;
    int global;
    int print_on_match;
} sed_command_t;

typedef struct sed_options {
    int quiet;
    sed_command_t command;
} sed_options_t;

static void usage(void)
{
    printf("usage: sed [-n] 's/old/new/[gp]' [file...]\n");
}

static int ensure_capacity(char** line, size_t* capacity, size_t needed)
{
    char* grown;
    size_t new_capacity;

    if (needed <= *capacity)
        return 0;

    new_capacity = *capacity ? *capacity : 128;
    while (new_capacity < needed)
        new_capacity *= 2;

    grown = realloc(*line, new_capacity);
    if (!grown)
        return -1;

    *line = grown;
    *capacity = new_capacity;
    return 0;
}

static int read_line_fd(int fd, char** line, size_t* capacity)
{
    char ch;
    size_t len = 0;
    int saw_any = 0;

    while (1) {
        int n = read(fd, &ch, 1);

        if (n < 0)
            return -1;
        if (n == 0)
            break;

        saw_any = 1;
        if (ch == '\n')
            break;

        if (ensure_capacity(line, capacity, len + 2) < 0)
            return -1;
        (*line)[len++] = ch;
    }

    if (!saw_any)
        return 0;

    if (ensure_capacity(line, capacity, len + 1) < 0)
        return -1;

    (*line)[len] = '\0';
    return 1;
}

static char* append_text(char* out, size_t* len, size_t* cap,
                         const char* text, size_t text_len)
{
    if (ensure_capacity(&out, cap, *len + text_len + 1) < 0) {
        free(out);
        return NULL;
    }

    memcpy(out + *len, text, text_len);
    *len += text_len;
    out[*len] = '\0';
    return out;
}

static char* apply_substitution(const char* line, const sed_command_t* cmd,
                                int* changed)
{
    const char* pattern = cmd->pattern;
    const char* repl = cmd->replacement;
    size_t pattern_len = strlen(pattern);
    size_t repl_len = strlen(repl);
    const char* cursor = line;
    char* out = NULL;
    size_t len = 0;
    size_t cap = 0;

    *changed = 0;

    if (pattern_len == 0)
        return strdup(line);

    while (*cursor) {
        const char* match = strstr(cursor, pattern);

        if (!match) {
            out = append_text(out, &len, &cap, cursor, strlen(cursor));
            return out;
        }

        out = append_text(out, &len, &cap, cursor, (size_t)(match - cursor));
        if (!out)
            return NULL;

        out = append_text(out, &len, &cap, repl, repl_len);
        if (!out)
            return NULL;

        *changed = 1;
        cursor = match + pattern_len;

        if (!cmd->global) {
            out = append_text(out, &len, &cap, cursor, strlen(cursor));
            return out;
        }
    }

    if (!out)
        out = strdup(line);

    return out;
}

static int parse_substitute(char* expr, sed_command_t* cmd)
{
    char delim;
    char* old;
    char* new_text;
    char* flags;

    if (!expr || expr[0] != 's' || expr[1] == '\0')
        return -1;

    delim = expr[1];
    old = expr + 2;
    new_text = strchr(old, delim);
    if (!new_text)
        return -1;
    *new_text++ = '\0';

    flags = strchr(new_text, delim);
    if (!flags)
        return -1;
    *flags++ = '\0';

    cmd->pattern = old;
    cmd->replacement = new_text;
    cmd->global = 0;
    cmd->print_on_match = 0;

    while (*flags) {
        if (*flags == 'g')
            cmd->global = 1;
        else if (*flags == 'p')
            cmd->print_on_match = 1;
        else
            return -1;
        flags++;
    }

    return 0;
}

static int sed_fd(int fd, const sed_options_t* opts)
{
    char* line = NULL;
    size_t capacity = 0;
    int result;
    int status = 0;

    while ((result = read_line_fd(fd, &line, &capacity)) > 0) {
        int changed = 0;
        char* output = apply_substitution(line, &opts->command, &changed);

        if (!output) {
            status = 1;
            break;
        }

        if (!opts->quiet) {
            printf("%s\n", output);
        } else if (opts->command.print_on_match && changed) {
            printf("%s\n", output);
        }

        free(output);
    }

    if (result < 0)
        status = 1;

    free(line);
    return status;
}

static int sed_file(const char* path, const sed_options_t* opts)
{
    int fd;
    int status;

    if (strcmp(path, "-") == 0)
        return sed_fd(STDIN_FILENO, opts);

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        printf("sed: cannot open %s\n", path);
        return 1;
    }

    status = sed_fd(fd, opts);
    close(fd);
    return status;
}

int main(int argc, char** argv)
{
    sed_options_t opts;
    char* expr;
    int arg = 1;
    int status = 0;

    memset(&opts, 0, sizeof(opts));

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        opts.quiet = 1;
        arg++;
    }

    if (arg >= argc) {
        usage();
        return 1;
    }

    expr = strdup(argv[arg++]);
    if (!expr || parse_substitute(expr, &opts.command) < 0) {
        printf("sed: unsupported expression\n");
        free(expr);
        usage();
        return 1;
    }

    if (arg >= argc) {
        status = sed_fd(STDIN_FILENO, &opts);
    } else {
        while (arg < argc) {
            if (sed_file(argv[arg], &opts) != 0)
                status = 1;
            arg++;
        }
    }

    free(expr);
    return status;
}
