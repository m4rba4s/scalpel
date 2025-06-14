#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/io.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <curses.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/inotify.h>

#define EC_SC 0x66
#define EC_DATA 0x62
#define TIMEOUT 1000000
#define BUF_LEN (10 * (sizeof(struct inotify_event) + 256))

bool gui_mode = false;

const char *field_names[] = {
    "FBCM", "FBGI", "FBAE", "FBCB", "FBW1",
    "FBW2", "RSVD6", "FBID", "FUAE", "FRPS"
};

void log_event(const char *fmt, ...) {
    if (gui_mode) return;
    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

int ec_wait_ibf() {
    int timeout = TIMEOUT;
    while ((inb(EC_SC) & 0x02) && timeout--);
    return timeout > 0;
}

int ec_wait_obf() {
    int timeout = TIMEOUT;
    while (!(inb(EC_SC) & 0x01) && timeout--);
    return timeout > 0;
}

void ec_init() {
    if (ioperm(EC_SC, 1, 1) || ioperm(EC_DATA, 1, 1)) {
        perror("ioperm");
        exit(1);
    }
}

uint8_t ec_read(uint8_t addr) {
    if (!ec_wait_ibf()) { log_event("EC IBF timeout before read command"); return 0xFF; }
    outb(0x80, EC_SC);
    if (!ec_wait_ibf()) { log_event("EC IBF timeout before address"); return 0xFF; }
    outb(addr, EC_DATA);
    if (!ec_wait_obf()) { log_event("EC OBF timeout during read"); return 0xFF; }
    uint8_t val = inb(EC_DATA);
    log_event("Read [0x%02X] = 0x%02X", addr, val);
    return val;
}

void ec_write(uint8_t addr, uint8_t value) {
    if (!ec_wait_ibf()) { log_event("EC IBF timeout before write command"); return; }
    outb(0x81, EC_SC);
    if (!ec_wait_ibf()) { log_event("EC IBF timeout before address"); return; }
    outb(addr, EC_DATA);
    if (!ec_wait_ibf()) { log_event("EC IBF timeout before value"); return; }
    outb(value, EC_DATA);
    if (!ec_wait_obf()) { log_event("EC OBF timeout after write"); return; }
    uint8_t check = ec_read(addr);
    log_event("Wrote [0x%02X] = 0x%02X (verify: 0x%02X)", addr, value, check);
}

void dump_ssrm_region() {
    log_event("Dumping SSRM region (0x50 - 0x59)");
    for (int i = 0; i < 10; i++) {
        uint8_t val = ec_read(0x50 + i);
        const char *name = field_names[i];
        printf("%s (0x%02X): 0x%02X\n", name, 0x50 + i, val);
    }
}

void signal_handler(int signum) {
    endwin();
    exit(0);
}

void gui_monitor(int interval_sec) {
    gui_mode = true;
    uint8_t prev[10] = {0};
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLACK);
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
    init_pair(3, COLOR_YELLOW, COLOR_BLACK);
    init_pair(4, COLOR_RED, COLOR_BLACK);

    signal(SIGINT, signal_handler);

    for (int i = 0; i < 10; i++) {
        prev[i] = ec_read(0x50 + i);
    }

    while (1) {
        clear();
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        mvprintw(0, 0, "[EC Monitor] %02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);

        for (int i = 0; i < 10; i++) {
            uint8_t curr = ec_read(0x50 + i);
            const char *name = field_names[i];

            int color = 2; // green
            if (curr != prev[i]) color = 3;
            if (curr == 0xFF) color = 4;

            attron(COLOR_PAIR(color));
            mvprintw(i + 2, 2, "%s (0x%02X): 0x%02X", name, 0x50 + i, curr);
            attroff(COLOR_PAIR(color));

            prev[i] = curr;
        }

        mvprintw(14, 2, "Press Ctrl+C to exit");
        refresh();
        sleep(interval_sec);
    }
    endwin();
}

void monitor_ssrm_region(int interval_sec) {
    uint8_t prev[10] = {0};
    int change_counter[10] = {0};
    for (int i = 0; i < 10; i++) {
        prev[i] = ec_read(0x50 + i);
    }

    while (1) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        printf("[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);

        bool any_change = false;
        for (int i = 0; i < 10; i++) {
            uint8_t curr = ec_read(0x50 + i);
            if (curr != prev[i]) {
                printf("%s (0x%02X): 0x%02X -> 0x%02X [Δ %d]  ", field_names[i], 0x50 + i, prev[i], curr, ++change_counter[i]);
                prev[i] = curr;
                any_change = true;
            }
        }
        if (any_change) printf("\n");
        fflush(stdout);
        sleep(interval_sec);
    }
}

void dump_uefi_vars() {
    DIR *d;
    struct dirent *dir;
    d = opendir("/sys/firmware/efi/efivars");
    if (!d) {
        perror("opendir");
        return;
    }
    printf("UEFI Variables:\n");
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_name[0] == '.') continue;
        printf("  %s\n", dir->d_name);
    }
    closedir(d);
}

void watch_uefi_changes() {
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        return;
    }
    int wd = inotify_add_watch(fd, "/sys/firmware/efi/efivars", IN_MODIFY | IN_CREATE | IN_DELETE);
    if (wd == -1) {
        perror("inotify_add_watch");
        close(fd);
        return;
    }
    char buf[BUF_LEN];
    printf("Watching UEFI variable changes... (Ctrl+C to stop)\n");
    while (1) {
        int len = read(fd, buf, BUF_LEN);
        if (len < 0) {
            perror("read");
            break;
        }
        int i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];
            printf("[%ld] Event: %s %s\n", time(NULL),
                (event->mask & IN_CREATE) ? "CREATE" :
                (event->mask & IN_DELETE) ? "DELETE" :
                (event->mask & IN_MODIFY) ? "MODIFY" : "UNKNOWN",
                event->name);
            i += sizeof(struct inotify_event) + event->len;
        }
    }
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s --dump\n", argv[0]);
        printf("  %s --read 0xADDR\n", argv[0]);
        printf("  %s --write 0xADDR=0xVAL\n", argv[0]);
        printf("  %s --monitor [seconds]\n", argv[0]);
        printf("  %s --gui [seconds]\n", argv[0]);
        printf("  %s --uefi-vars\n", argv[0]);
        printf("  %s --uefi-watch\n", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "--uefi-vars")) {
        dump_uefi_vars();
        return 0;
    }
    if (!strcmp(argv[1], "--uefi-watch")) {
        watch_uefi_changes();
        return 0;
    }

    ec_init();

    if (!strcmp(argv[1], "--dump")) {
        dump_ssrm_region();
    } else if (!strcmp(argv[1], "--read") && argc == 3) {
        uint8_t addr = (uint8_t)strtol(argv[2], NULL, 0);
        uint8_t val = ec_read(addr);
        printf("[0x%02X] = 0x%02X\n", addr, val);
    } else if (!strcmp(argv[1], "--write") && argc == 3) {
        uint8_t addr, val;
        if (sscanf(argv[2], "0x%hhX=0x%hhX", &addr, &val) == 2) {
            ec_write(addr, val);
        } else {
            fprintf(stderr, "Invalid format. Use 0xADDR=0xVAL\n");
            return 1;
        }
    } else if (!strcmp(argv[1], "--monitor")) {
        int interval = 1;
        if (argc == 3) interval = atoi(argv[2]);
        monitor_ssrm_region(interval);
    } else if (!strcmp(argv[1], "--gui")) {
        int interval = 1;
        if (argc == 3) interval = atoi(argv[2]);
        gui_monitor(interval);
    } else {
        fprintf(stderr, "Unknown option or wrong argument count.\n");
        return 1;
    }

    return 0;
}
