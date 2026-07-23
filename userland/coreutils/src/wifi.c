/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/wifi.c
 * Layer: Userland / network utilities
 *
 * Responsibilities:
 * - List Wi-Fi networks and persistent connection profiles.
 * - Request hot association, disconnection and default-profile reload.
 * - Keep credentials in root-managed files rather than command arguments.
 *
 * Notes:
 * - Profiles live in /etc/wifi.d and use the same key=value format as the
 *   backward-compatible /etc/wifi.conf file.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WIFI_CONTROL_PATH "/dev/netctl"
#define WIFI_DEFAULT_CONFIG "/etc/wifi.conf"
#define WIFI_PROFILE_DIRECTORY "/etc/wifi.d"
#define WIFI_DEFAULT_INTERFACE "wlan0"
#define WIFI_PATH_SIZE 160
#define WIFI_COMMAND_SIZE 256
#define WIFI_BUFFER_SIZE 512
#define WIFI_SSID_SIZE 33
#define WIFI_PASSWORD_SIZE 65
#define WIFI_MAX_CONNECT_ATTEMPTS 3

static void usage(void)
{
    fprintf(stderr,
        "usage: wifi status [interface]\n"
        "       wifi scan [interface]\n"
        "       wifi profiles\n"
        "       wifi connect <profile-or-SSID> [interface]\n"
        "       wifi reload [interface]\n"
        "       wifi disconnect [interface]\n");
}

static int wifi_control(const char *command)
{
    char buffer[WIFI_BUFFER_SIZE];
    char prefix[32] = {0};
    size_t prefix_length = 0u;
    ssize_t count;
    int fd;
    int failed = 0;
    int remote_error = 0;

    fd = open(WIFI_CONTROL_PATH, O_RDWR, 0);
    if (fd < 0) {
        fprintf(stderr, "wifi: cannot open %s: %s\n",
                WIFI_CONTROL_PATH, strerror(errno));
        return 1;
    }
    if (write(fd, command, strlen(command)) != (ssize_t)strlen(command)) {
        fprintf(stderr, "wifi: request failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        size_t copy = (size_t)count;

        if (prefix_length < sizeof(prefix) - 1u) {
            if (copy > sizeof(prefix) - 1u - prefix_length)
                copy = sizeof(prefix) - 1u - prefix_length;
            memcpy(prefix + prefix_length, buffer, copy);
            prefix_length += copy;
            prefix[prefix_length] = '\0';
        }
        if (write(STDOUT_FILENO, buffer, (size_t)count) != count) {
            fprintf(stderr, "wifi: output failed: %s\n", strerror(errno));
            failed = 1;
            break;
        }
    }
    if (count < 0) {
        fprintf(stderr, "wifi: response failed: %s\n", strerror(errno));
        failed = 1;
    }
    close(fd);
    if (sscanf(prefix, "error %d", &remote_error) == 1)
        return remote_error < 0 ? remote_error : -remote_error;
    return failed ? -EIO : 0;
}

static int wifi_profile_read(const char *path, char *ssid,
                             size_t ssid_capacity, char *security,
                             size_t security_capacity, char *country,
                             size_t country_capacity, char *password,
                             size_t password_capacity)
{
    char line[192];
    FILE *file;

    if (!path || !ssid || !security)
        return -1;
    ssid[0] = '\0';
    snprintf(security, security_capacity, "wpa2");
    if (country && country_capacity != 0u)
        snprintf(country, country_capacity, "00");
    if (password && password_capacity != 0u)
        password[0] = '\0';
    file = fopen(path, "r");
    if (!file)
        return -1;
    while (fgets(line, sizeof(line), file)) {
        char *newline = strchr(line, '\n');

        if (newline)
            *newline = '\0';
        if (strncmp(line, "ssid=", 5u) == 0)
            snprintf(ssid, ssid_capacity, "%s", line + 5u);
        else if (strncmp(line, "security=", 9u) == 0)
            snprintf(security, security_capacity, "%s", line + 9u);
        else if (country && strncmp(line, "country=", 8u) == 0)
            snprintf(country, country_capacity, "%s", line + 8u);
        else if (password && strncmp(line, "password=", 9u) == 0)
            snprintf(password, password_capacity, "%s", line + 9u);
    }
    fclose(file);
    return ssid[0] ? 0 : -1;
}

static int wifi_profile_path(const char *requested, char *path,
                             size_t capacity)
{
    DIR *directory;
    struct dirent *entry;

    if (!requested || !path || capacity == 0u)
        return -1;
    if (requested[0] == '/') {
        if (access(requested, R_OK) < 0)
            return -1;
        snprintf(path, capacity, "%s", requested);
        return 0;
    }
    if (snprintf(path, capacity, "%s/%s.conf",
                 WIFI_PROFILE_DIRECTORY, requested) < (int)capacity &&
        access(path, R_OK) == 0)
        return 0;

    directory = opendir(WIFI_PROFILE_DIRECTORY);
    if (!directory)
        return -1;
    while ((entry = readdir(directory)) != NULL) {
        char ssid[64];
        char security[16];
        size_t length = strlen(entry->d_name);

        if (length < 6u ||
            strcmp(entry->d_name + length - 5u, ".conf") != 0)
            continue;
        if (snprintf(path, capacity, "%s/%s", WIFI_PROFILE_DIRECTORY,
                     entry->d_name) >= (int)capacity)
            continue;
        if (wifi_profile_read(path, ssid, sizeof(ssid), security,
                              sizeof(security), NULL, 0u, NULL, 0u) == 0 &&
            strcmp(ssid, requested) == 0) {
            closedir(directory);
            return 0;
        }
    }
    closedir(directory);
    return -1;
}

static int wifi_profiles(void)
{
    DIR *directory;
    struct dirent *entry;
    int found = 0;

    directory = opendir(WIFI_PROFILE_DIRECTORY);
    if (!directory) {
        fprintf(stderr, "wifi: cannot open %s: %s\n",
                WIFI_PROFILE_DIRECTORY, strerror(errno));
        return 1;
    }
    printf("%-24s %-32s %s\n", "PROFILE", "SSID", "SECURITY");
    while ((entry = readdir(directory)) != NULL) {
        char path[WIFI_PATH_SIZE];
        char ssid[64];
        char security[16];
        char name[64];
        size_t length = strlen(entry->d_name);

        if (length < 6u ||
            strcmp(entry->d_name + length - 5u, ".conf") != 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s",
                     WIFI_PROFILE_DIRECTORY, entry->d_name) >=
            (int)sizeof(path))
            continue;
        if (wifi_profile_read(path, ssid, sizeof(ssid), security,
                              sizeof(security), NULL, 0u, NULL, 0u) < 0)
            continue;
        if (length - 5u >= sizeof(name))
            continue;
        memcpy(name, entry->d_name, length - 5u);
        name[length - 5u] = '\0';
        printf("%-24s %-32s %s\n", name, ssid, security);
        found++;
    }
    closedir(directory);
    return found ? 0 : 1;
}

static int wifi_require_root(const char *action)
{
    if (geteuid() == 0)
        return 0;
    fprintf(stderr, "wifi: %s requires root\n", action);
    return -1;
}

static int wifi_valid_country(const char *country)
{
    return country && strlen(country) == 2u &&
           isalpha((unsigned char)country[0]) &&
           isalpha((unsigned char)country[1]);
}

static int wifi_read_country(char country[3])
{
    char line[96];
    FILE *file;

    snprintf(country, 3u, "00");
    file = fopen(WIFI_DEFAULT_CONFIG, "r");
    if (!file)
        return -1;
    while (fgets(line, sizeof(line), file)) {
        char *value;
        char *newline;

        if (strncmp(line, "country=", 8u) != 0)
            continue;
        value = line + 8u;
        newline = strpbrk(value, "\r\n");
        if (newline)
            *newline = '\0';
        if (!wifi_valid_country(value))
            break;
        country[0] = (char)toupper((unsigned char)value[0]);
        country[1] = (char)toupper((unsigned char)value[1]);
        country[2] = '\0';
        fclose(file);
        return 0;
    }
    fclose(file);
    return -1;
}

static int wifi_prompt_country(char country[3])
{
    char input[16];
    int attempt;

    for (attempt = 0; attempt < 3; attempt++) {
        char *newline;

        fprintf(stderr,
                "Country code (ISO 3166-1 alpha-2, for example FR): ");
        fflush(stderr);
        if (!fgets(input, sizeof(input), stdin))
            return -1;
        newline = strpbrk(input, "\r\n");
        if (newline)
            *newline = '\0';
        fprintf(stderr, "%s\n", input);
        if (wifi_valid_country(input)) {
            country[0] = (char)toupper((unsigned char)input[0]);
            country[1] = (char)toupper((unsigned char)input[1]);
            country[2] = '\0';
            return 0;
        }
        fprintf(stderr, "wifi: enter a two-letter country code\n");
    }
    return -1;
}

static int wifi_profile_name(const char *ssid, char *name, size_t capacity)
{
    size_t input = 0u;
    size_t output = 0u;

    if (!ssid || !name || capacity < 2u)
        return -1;
    while (ssid[input] != '\0' && output + 1u < capacity) {
        unsigned char ch = (unsigned char)ssid[input++];

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
            ch == '.')
            name[output++] = (char)ch;
        else if (ch == ' ')
            name[output++] = '-';
        else if (ch < 0x20u || ch == 0x7fu)
            return -1;
        else
            name[output++] = '_';
    }
    name[output] = '\0';
    return output != 0u && ssid[input] == '\0' ? 0 : -1;
}

static int wifi_read_password(const char *ssid, char *password,
                              size_t capacity)
{
    char *newline;

    if (!ssid || !password || capacity == 0u)
        return -1;
    fprintf(stderr, "Wi-Fi password for %s (empty for open network): ", ssid);
    fflush(stderr);
    if (!fgets(password, capacity, stdin)) {
        fputc('\n', stderr);
        return -1;
    }
    newline = strchr(password, '\n');
    if (!newline) {
        int ch;

        while ((ch = fgetc(stdin)) != '\n' && ch != EOF)
            ;
        fprintf(stderr, "%s\n", password);
        fprintf(stderr, "wifi: password is too long\n");
        return -1;
    }
    *newline = '\0';
    fprintf(stderr, "%s\n", password);
    if (password[0] != '\0' &&
        (strlen(password) < 8u || strlen(password) > 64u)) {
        fprintf(stderr,
                "wifi: WPA2 password must contain between 8 and 64 characters\n");
        return -1;
    }
    return 0;
}

static int wifi_write_profile_file(const char *path, const char *country,
                                   const char *ssid, const char *password)
{
    char contents[256];
    const char *security = password[0] ? "wpa2" : "open";
    int length;
    int fd;

    if (country) {
        length = snprintf(contents, sizeof(contents),
                          "country=%s\nssid=%s\nsecurity=%s\npassword=%s\n",
                          country, ssid, security, password);
    } else {
        length = snprintf(contents, sizeof(contents),
                          "ssid=%s\nsecurity=%s\npassword=%s\n",
                          ssid, security, password);
    }
    if (length < 0 || (size_t)length >= sizeof(contents))
        return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "wifi: cannot create temporary profile: %s\n",
                strerror(errno));
        return -1;
    }
    if (write(fd, contents, (size_t)length) != (ssize_t)length) {
        fprintf(stderr, "wifi: cannot write temporary profile: %s\n",
                strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

static int wifi_profile_default_name(const char *path, char *name,
                                     size_t capacity)
{
    const char *base;
    size_t length;

    if (!path || !name || capacity == 0u)
        return -1;
    base = strrchr(path, '/');
    base = base ? base + 1u : path;
    length = strlen(base);
    if (length <= 5u || strcmp(base + length - 5u, ".conf") != 0 ||
        length - 5u >= capacity)
        return -1;
    memcpy(name, base, length - 5u);
    name[length - 5u] = '\0';
    return 0;
}

static int wifi_write_default_config(const char *country,
                                     const char *profile_name)
{
    char temporary[WIFI_PATH_SIZE];
    char contents[160];
    int length;
    int fd;

    if (profile_name) {
        length = snprintf(contents, sizeof(contents),
                          "country=%s\ndefault=%s\n",
                          country, profile_name);
    } else {
        length = snprintf(contents, sizeof(contents), "country=%s\n",
                          country);
    }
    if (length < 0 || (size_t)length >= sizeof(contents) ||
        snprintf(temporary, sizeof(temporary), "/etc/.wifi-%ld.conf.tmp",
                 (long)getpid()) >= (int)sizeof(temporary))
        return -1;
    (void)unlink(temporary);
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, contents, (size_t)length) != (ssize_t)length) {
        close(fd);
        unlink(temporary);
        return -1;
    }
    close(fd);
    if (rename(temporary, WIFI_DEFAULT_CONFIG) < 0) {
        unlink(temporary);
        return -1;
    }
    (void)chmod(WIFI_DEFAULT_CONFIG, 0644);
    return 0;
}

static int wifi_save_profile(const char *profile_path, const char *country,
                             const char *ssid, const char *password)
{
    char temporary[WIFI_PATH_SIZE];
    char profile_name[64];

    if (snprintf(temporary, sizeof(temporary),
                 WIFI_PROFILE_DIRECTORY "/.wifi-save-%ld.tmp",
                 (long)getpid()) >= (int)sizeof(temporary))
        return -1;
    (void)unlink(temporary);
    if (wifi_write_profile_file(temporary, country, ssid, password) < 0)
        return -1;
    if (rename(temporary, profile_path) < 0) {
        unlink(temporary);
        return -1;
    }
    (void)chmod(profile_path, 0600);
    if (wifi_profile_default_name(profile_path, profile_name,
                                  sizeof(profile_name)) < 0 ||
        wifi_write_default_config(country, profile_name) < 0)
        return -1;
    return 0;
}

static int wifi_connect_path(const char *interface, const char *path)
{
    char command[WIFI_COMMAND_SIZE];

    if (snprintf(command, sizeof(command), "wifi connect %s %s",
                 interface, path) >= (int)sizeof(command)) {
        fprintf(stderr, "wifi: profile path is too long\n");
        return 1;
    }
    return wifi_control(command);
}

static int wifi_scan_interactive(const char *interface)
{
    char command[WIFI_COMMAND_SIZE];
    char country[3];

    if (wifi_read_country(country) < 0) {
        if (wifi_require_root("scan setup") < 0)
            return 1;
        if (wifi_prompt_country(country) < 0) {
            fprintf(stderr, "wifi: a valid country code is required\n");
            return 1;
        }
        if (wifi_write_default_config(country, NULL) < 0) {
            fprintf(stderr, "wifi: cannot save country configuration: %s\n",
                    strerror(errno));
            return 1;
        }
    }
    if (geteuid() == 0) {
        if (snprintf(command, sizeof(command), "wifi country %s %s",
                     interface, country) >= (int)sizeof(command))
            return 1;
        if (wifi_control(command) != 0)
            return 1;
    }
    if (snprintf(command, sizeof(command), "wifi scan %s", interface) >=
        (int)sizeof(command))
        return 1;
    return wifi_control(command);
}

static int wifi_connect_interactive(const char *requested,
                                    const char *interface)
{
    char profile_path[WIFI_PATH_SIZE];
    char trial_path[WIFI_PATH_SIZE];
    char profile_name[64];
    char ssid[WIFI_SSID_SIZE];
    char security[16];
    char country[4] = "00";
    char password[WIFI_PASSWORD_SIZE];
    int have_profile;
    int attempts = 0;

    if (mkdir(WIFI_PROFILE_DIRECTORY, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "wifi: cannot create %s: %s\n",
                WIFI_PROFILE_DIRECTORY, strerror(errno));
        return 1;
    }
    have_profile =
        wifi_profile_path(requested, profile_path, sizeof(profile_path)) == 0;
    if (have_profile) {
        if (wifi_profile_read(profile_path, ssid, sizeof(ssid), security,
                              sizeof(security), country, sizeof(country),
                              password,
                              sizeof(password)) < 0) {
            fprintf(stderr, "wifi: invalid profile %s\n", profile_path);
            return 1;
        }
    } else {
        snprintf(ssid, sizeof(ssid), "%s", requested);
        if (ssid[0] == '\0' || strlen(requested) >= sizeof(ssid)) {
            fprintf(stderr, "wifi: invalid SSID\n");
            return 1;
        }
        if (wifi_profile_name(ssid, profile_name, sizeof(profile_name)) < 0 ||
            snprintf(profile_path, sizeof(profile_path), "%s/%s.conf",
                     WIFI_PROFILE_DIRECTORY, profile_name) >=
            (int)sizeof(profile_path)) {
            fprintf(stderr, "wifi: cannot derive a profile name from SSID\n");
            return 1;
        }
        password[0] = '\0';
    }
    if (!wifi_valid_country(country) &&
        wifi_read_country(country) < 0 &&
        wifi_prompt_country(country) < 0) {
        fprintf(stderr, "wifi: a valid country code is required\n");
        return 1;
    }

    while (attempts < WIFI_MAX_CONNECT_ATTEMPTS) {
        int connect_result;

        if (!have_profile || attempts != 0) {
            if (wifi_read_password(ssid, password, sizeof(password)) < 0)
                return 1;
        }
        if (snprintf(trial_path, sizeof(trial_path),
                     WIFI_PROFILE_DIRECTORY "/.wifi-%ld-%d.tmp",
                     (long)getpid(), attempts) >= (int)sizeof(trial_path))
            return 1;
        (void)unlink(trial_path);
        if (wifi_write_profile_file(trial_path, country, ssid, password) < 0)
            return 1;
        connect_result = wifi_connect_path(interface, trial_path);
        if (connect_result == 0) {
            unlink(trial_path);
            if (wifi_save_profile(profile_path, country, ssid, password) < 0) {
                fprintf(stderr,
                        "wifi: connected, but cannot save configuration: %s\n",
                        strerror(errno));
                memset(password, 0, sizeof(password));
                return 1;
            }
            printf("wifi: profile saved to %s\n", profile_path);
            memset(password, 0, sizeof(password));
            return 0;
        }
        unlink(trial_path);
        memset(password, 0, sizeof(password));
        if (connect_result != -EACCES) {
            fprintf(stderr,
                    "wifi: connection setup failed (%d); "
                    "the password was not rejected\n",
                    connect_result);
            return 1;
        }
        attempts++;
        if (attempts < WIFI_MAX_CONNECT_ATTEMPTS)
            fprintf(stderr, "wifi: authentication failed, try again\n");
    }
    fprintf(stderr, "wifi: connection failed after %d attempts\n",
            WIFI_MAX_CONNECT_ATTEMPTS);
    return 1;
}

int main(int argc, char **argv)
{
    char command[WIFI_COMMAND_SIZE];
    const char *interface = WIFI_DEFAULT_INTERFACE;

    if (argc < 2) {
        usage();
        return 1;
    }
    if (strcmp(argv[1], "profiles") == 0) {
        if (argc != 2) {
            usage();
            return 1;
        }
        return wifi_profiles();
    }
    if (strcmp(argv[1], "connect") == 0) {
        if (argc < 3 || argc > 4) {
            usage();
            return 1;
        }
        if (wifi_require_root(argv[1]) < 0)
            return 1;
        if (argc == 4)
            interface = argv[3];
        return wifi_connect_interactive(argv[2], interface);
    }
    if (strcmp(argv[1], "scan") == 0) {
        if (argc > 3) {
            usage();
            return 1;
        }
        if (argc == 3)
            interface = argv[2];
        return wifi_scan_interactive(interface);
    }
    if (strcmp(argv[1], "status") != 0 &&
        strcmp(argv[1], "reload") != 0 &&
        strcmp(argv[1], "disconnect") != 0) {
        usage();
        return 1;
    }
    if (argc > 3) {
        usage();
        return 1;
    }
    if ((strcmp(argv[1], "reload") == 0 ||
         strcmp(argv[1], "disconnect") == 0) &&
        wifi_require_root(argv[1]) < 0)
        return 1;
    if (argc == 3)
        interface = argv[2];
    snprintf(command, sizeof(command), "wifi %s %s", argv[1], interface);
    return wifi_control(command);
}
