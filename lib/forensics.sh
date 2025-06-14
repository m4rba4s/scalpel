#!/bin/bash
#
# Утилиты для форензического анализа
# Часть системы защиты Fedora 41

# Создание форензической копии системы
create_forensic_snapshot() {
    local target_dir=$1
    
    if [[ -z "$target_dir" ]]; then
        target_dir="${FORENSIC_DIR}/snapshot_$(date +%Y%m%d_%H%M%S)"
    fi
    
    log "INFO" "Создание форензической копии системы в $target_dir..."
    
    # Создание директории для форензики
    mkdir -p "$target_dir"
    
    # Сбор информации о системе
    collect_system_info "$target_dir"
    
    # Сбор информации о процессах
    collect_process_info "$target_dir"
    
    # Сбор информации о сети
    collect_network_info "$target_dir"
    
    # Сбор информации о файловой системе
    collect_filesystem_info "$target_dir"
    
    # Копирование важных логов
    collect_logs "$target_dir"
    
    log "INFO" "Форензическая копия создана в $target_dir"
    
    return 0
}

# Сбор информации о системе
collect_system_info() {
    local target_dir=$1
    
    log "INFO" "Сбор общей информации о системе..."
    
    # Информация о ядре и ОС
    uname -a > "$target_dir/uname.txt"
    cat /etc/fedora-release > "$target_dir/os_release.txt" 2>/dev/null || true
    
    # Информация о железе
    if command -v dmidecode &> /dev/null; then
        dmidecode > "$target_dir/dmidecode.txt" 2>/dev/null || true
    fi
    
    # Информация о CPU
    cat /proc/cpuinfo > "$target_dir/cpuinfo.txt"
    
    # Информация о памяти
    cat /proc/meminfo > "$target_dir/meminfo.txt"
    free -m > "$target_dir/free.txt"
    
    # Информация о времени
    date > "$target_dir/date.txt"
    if command -v timedatectl &> /dev/null; then
        timedatectl > "$target_dir/timedatectl.txt"
    fi
    
    # Информация о загрузке системы
    uptime > "$target_dir/uptime.txt"
    cat /proc/loadavg > "$target_dir/loadavg.txt"
    
    # Информация о загруженных модулях ядра
    lsmod > "$target_dir/lsmod.txt"
    
    # Информация о пользователях
    cat /etc/passwd > "$target_dir/passwd.txt"
    cat /etc/shadow > "$target_dir/shadow.txt" 2>/dev/null || true
    cat /etc/group > "$target_dir/group.txt"
    
    # История пользователей
    find /home -name ".bash_history" -exec cp {} "$target_dir/bash_history_{}" \; 2>/dev/null || true
    
    # Переменные окружения
    env > "$target_dir/env.txt"
    
    log "INFO" "Информация о системе собрана"
}

# Сбор информации о процессах
collect_process_info() {
    local target_dir=$1
    
    log "INFO" "Сбор информации о процессах..."
    
    # Список процессов (различные форматы)
    ps aux > "$target_dir/ps_aux.txt"
    ps -efl > "$target_dir/ps_efl.txt"
    ps -eo pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,time,cmd > "$target_dir/ps_detailed.txt"
    
    # Информация о процессах из /proc
    mkdir -p "$target_dir/proc"
    
    for pid in /proc/[0-9]*; do
        if [[ -d "$pid" ]]; then
            pid_num=$(basename "$pid")
            mkdir -p "$target_dir/proc/$pid_num"
            
            # Копирование основных файлов процесса
            cp "$pid/cmdline" "$target_dir/proc/$pid_num/" 2>/dev/null || true
            cp "$pid/environ" "$target_dir/proc/$pid_num/" 2>/dev/null || true
            cp "$pid/status" "$target_dir/proc/$pid_num/" 2>/dev/null || true
            cp "$pid/maps" "$target_dir/proc/$pid_num/" 2>/dev/null || true
            
            # Копирование файловых дескрипторов
            mkdir -p "$target_dir/proc/$pid_num/fd"
            ls -la "$pid/fd/" > "$target_dir/proc/$pid_num/fd/list.txt" 2>/dev/null || true
        fi
    done
    
    # Информация о запущенных службах
    if command -v systemctl &> /dev/null; then
        systemctl list-units --type=service > "$target_dir/systemctl_services.txt"
    fi
    
    # Информация о cron-заданиях
    if [[ -d "/var/spool/cron" ]]; then
        mkdir -p "$target_dir/cron"
        cp -r /var/spool/cron/* "$target_dir/cron/" 2>/dev/null || true
    fi
    cp -r /etc/cron* "$target_dir/" 2>/dev/null || true
    
    log "INFO" "Информация о процессах собрана"
}

# Сбор информации о сети
collect_network_info() {
    local target_dir=$1
    
    log "INFO" "Сбор информации о сети..."
    
    # Информация о сетевых интерфейсах
    ip addr > "$target_dir/ip_addr.txt"
    ip route > "$target_dir/ip_route.txt"
    
    # Информация о DNS
    cp /etc/hosts "$target_dir/hosts.txt" 2>/dev/null || true
    cp /etc/resolv.conf "$target_dir/resolv.conf" 2>/dev/null || true
    
    # Информация о сетевых соединениях
    ss -tunap > "$target_dir/ss_tunap.txt"
    netstat -tunap > "$target_dir/netstat_tunap.txt" 2>/dev/null || true
    
    # Информация о прослушиваемых портах
    ss -tulpn > "$target_dir/listening_ports.txt"
    
    # Информация о правилах iptables
    iptables-save > "$target_dir/iptables.txt" 2>/dev/null || true
    
    # Информация о правилах nftables
    if command -v nft &> /dev/null; then
        nft list ruleset > "$target_dir/nftables.txt" 2>/dev/null || true
    fi
    
    # ARP-таблица
    ip neigh > "$target_dir/arp.txt"
    
    # Проверка открытых файлов сетевыми процессами
    lsof -i > "$target_dir/lsof_network.txt" 2>/dev/null || true
    
    log "INFO" "Информация о сети собрана"
}

# Сбор информации о файловой системе
collect_filesystem_info() {
    local target_dir=$1
    
    log "INFO" "Сбор информации о файловой системе..."
    
    # Информация о дисках и разделах
    df -h > "$target_dir/df.txt"
    mount > "$target_dir/mount.txt"
    cat /proc/mounts > "$target_dir/proc_mounts.txt"
    
    # Информация о файловых системах
    if command -v lsblk &> /dev/null; then
        lsblk -f > "$target_dir/lsblk.txt"
    fi
    
    # Информация о загрузчике
    if [[ -d "/boot/grub2" ]]; then
        cp /boot/grub2/grub.cfg "$target_dir/grub.cfg" 2>/dev/null || true
    fi
    
    # Поиск SUID/SGID файлов
    find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "$target_dir/suid_sgid_files.txt"
    
    # Поиск файлов с измененными временными метками
    find /bin /sbin /usr/bin /usr/sbin -type f -mtime -3 -ls 2>/dev/null > "$target_dir/recently_modified_binaries.txt"
    
    # Поиск файлов в /tmp, /dev/shm
    ls -la /tmp > "$target_dir/tmp_files.txt" 2>/dev/null || true
    ls -la /dev/shm > "$target_dir/dev_shm_files.txt" 2>/dev/null || true
    
    # Хэши критичных системных файлов
    if command -v sha256sum &> /dev/null; then
        mkdir -p "$target_dir/hashes"
        
        # Создание хэшей для основных системных бинарников
        find /bin /sbin /usr/bin /usr/sbin -type f -name "ssh*" -o -name "su" -o -name "sudo" 2>/dev/null | \
        xargs sha256sum 2>/dev/null > "$target_dir/hashes/critical_binaries.txt" || true
    fi
    
    log "INFO" "Информация о файловой системе собрана"
}

# Сбор логов системы
collect_logs() {
    local target_dir=$1
    
    log "INFO" "Сбор логов системы..."
    
    # Создание директории для логов
    mkdir -p "$target_dir/logs"
    
    # Копирование основных лог-файлов
    cp /var/log/messages "$target_dir/logs/" 2>/dev/null || true
    cp /var/log/secure "$target_dir/logs/" 2>/dev/null || true
    cp /var/log/audit/audit.log "$target_dir/logs/" 2>/dev/null || true
    cp /var/log/dmesg "$target_dir/logs/" 2>/dev/null || true
    cp /var/log/wtmp "$target_dir/logs/" 2>/dev/null || true
    cp /var/log/btmp "$target_dir/logs/" 2>/dev/null || true
    
    # История команд root
    cp /root/.bash_history "$target_dir/logs/root_bash_history.txt" 2>/dev/null || true
    
    # Логи SSH
    cp /var/log/secure "$target_dir/logs/ssh_secure.log" 2>/dev/null || true
    
    # Логи журнала systemd
    if command -v journalctl &> /dev/null; then
        journalctl -b > "$target_dir/logs/journalctl.log" 2>/dev/null || true
    fi
    
    # Логи веб-сервера (если есть)
    if [[ -d "/var/log/httpd" ]]; then
        cp -r /var/log/httpd "$target_dir/logs/" 2>/dev/null || true
    fi
    if [[ -d "/var/log/nginx" ]]; then
        cp -r /var/log/nginx "$target_dir/logs/" 2>/dev/null || true
    fi
    
    # Логи suricata, если настроены
    local suricata_logs=$(jq -r '.network.ids.log_path' "$CONFIG_FILE" 2>/dev/null)
    if [[ -d "$suricata_logs" ]]; then
        cp -r "$suricata_logs" "$target_dir/logs/suricata" 2>/dev/null || true
    fi
    
    log "INFO" "Логи системы собраны"
}

# Анализ возможного вторжения
analyze_intrusion() {
    local forensic_dir=$1
    
    if [[ -z "$forensic_dir" ]]; then
        log "ERROR" "Необходимо указать директорию с форензическими данными"
        return 1
    fi
    
    log "INFO" "Анализ возможного вторжения по форензическим данным..."
    
    # Проверка наличия директории
    if [[ ! -d "$forensic_dir" ]]; then
        log "ERROR" "Директория $forensic_dir не существует"
        return 1
    fi
    
    # Анализ потенциально подозрительных процессов
    if [[ -f "$forensic_dir/ps_aux.txt" ]]; then
        log "INFO" "Анализ подозрительных процессов..."
        
        # Поиск потенциально вредоносных процессов
        grep -E "nc -|ncat|\.sh|\.py|wget http|curl -|perl -e|bash -i" "$forensic_dir/ps_aux.txt" > "$forensic_dir/suspicious_processes.txt"
        
        # Подсчет количества подозрительных процессов
        local suspicious_count=$(wc -l < "$forensic_dir/suspicious_processes.txt")
        log "INFO" "Найдено потенциально подозрительных процессов: $suspicious_count"
    fi
    
    # Анализ сетевых соединений
    if [[ -f "$forensic_dir/ss_tunap.txt" ]]; then
        log "INFO" "Анализ подозрительных сетевых соединений..."
        
        # Поиск соединений с необычными портами
        grep -E ":4444|:1337|:6666|:31337" "$forensic_dir/ss_tunap.txt" > "$forensic_dir/suspicious_connections.txt"
        
        # Поиск исходящих соединений к нестандартным портам
        grep -v -E ":80|:443|:53|:22" "$forensic_dir/ss_tunap.txt" | grep "ESTAB" >> "$forensic_dir/suspicious_connections.txt"
        
        # Подсчет количества подозрительных соединений
        local suspicious_conn_count=$(wc -l < "$forensic_dir/suspicious_connections.txt")
        log "INFO" "Найдено потенциально подозрительных соединений: $suspicious_conn_count"
    fi
    
    # Анализ модифицированных системных файлов
    if [[ -f "$forensic_dir/recently_modified_binaries.txt" ]]; then
        log "INFO" "Анализ недавно модифицированных системных файлов..."
        
        # Подсчет количества недавно модифицированных системных файлов
        local modified_count=$(wc -l < "$forensic_dir/recently_modified_binaries.txt")
        log "INFO" "Найдено недавно модифицированных системных файлов: $modified_count"
    fi
    
    # Анализ логов на признаки компрометации
    if [[ -d "$forensic_dir/logs" ]]; then
        log "INFO" "Анализ логов на признаки компрометации..."
        
        # Поиск попыток брутфорса SSH
        grep "Failed password" "$forensic_dir/logs/secure" 2>/dev/null | sort | uniq -c | sort -nr > "$forensic_dir/ssh_bruteforce.txt" || true
        
        # Поиск успешных входов в систему
        grep "Accepted password" "$forensic_dir/logs/secure" 2>/dev/null > "$forensic_dir/successful_logins.txt" || true
        
        # Поиск добавления пользователей
        grep -E "useradd|adduser" "$forensic_dir/logs/secure" 2>/dev/null > "$forensic_dir/user_additions.txt" || true
        
        # Поиск исполнения sudo
        grep "sudo:" "$forensic_dir/logs/secure" 2>/dev/null > "$forensic_dir/sudo_usage.txt" || true
    fi
    
    log "INFO" "Анализ возможного вторжения завершен. Результаты доступны в $forensic_dir"
    
    return 0
}

setup_forensics() {
    log "INFO" "Setting up forensic tools..."
    # Add forensic setup steps here
} 