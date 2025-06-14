#!/bin/bash
#
# Утилиты для работы с системой
# Часть системы защиты Fedora 41

# Настройка системного мониторинга
setup_system_monitoring() {
    log "INFO" "Настройка системного мониторинга..."
    
    # Настройка auditd, если установлен
    if command -v auditctl &> /dev/null; then
        log "INFO" "Настройка системы аудита..."
        
        # Мониторинг изменений в критичных директориях
        auditctl -w /etc/passwd -p wa -k user_modification
        auditctl -w /etc/shadow -p wa -k user_modification
        auditctl -w /etc/sudoers -p wa -k sudo_modification
        auditctl -w /etc/ssh/sshd_config -p wa -k ssh_modification
        
        # Мониторинг запуска привилегированных команд
        auditctl -a always,exit -F path=/usr/bin/sudo -F perm=x -k sudo_execution
        auditctl -a always,exit -F path=/bin/su -F perm=x -k su_execution
        
        # Мониторинг изменений в системных бинарниках
        auditctl -w /usr/bin -p wa -k binary_modification
        auditctl -w /usr/sbin -p wa -k binary_modification
        auditctl -w /bin -p wa -k binary_modification
        auditctl -w /sbin -p wa -k binary_modification
        
        log "INFO" "Система аудита настроена"
    else
        log "WARNING" "auditd не установлен. Некоторые функции мониторинга будут недоступны."
    fi
    
    # Настройка мониторинга целостности системы
    setup_integrity_monitoring
    
    log "INFO" "Системный мониторинг настроен"
}

# Настройка мониторинга целостности системы
setup_integrity_monitoring() {
    log "INFO" "Настройка мониторинга целостности файлов..."
    
    # Создание директории для хэшей
    mkdir -p "${SCRIPT_DIR}/hashes"
    
    # Создание хэшей для ключевых системных файлов
    log "INFO" "Создание базовых хэшей системных файлов..."
    
    # Мониторинг файлов из конфигурации
    local watch_dirs=$(jq -r '.monitoring.files.watch_dirs[]' "$CONFIG_FILE")
    local exclude_patterns=$(jq -r '.monitoring.files.exclude_patterns[]' "$CONFIG_FILE")
    
    # Создание шаблона grep для исключений
    local exclude_grep=""
    for pattern in $exclude_patterns; do
        exclude_grep="${exclude_grep}|${pattern}"
    done
    exclude_grep=$(echo "$exclude_grep" | sed 's/^|//')
    
    # Для каждой директории создаем список файлов и их хэшей
    for dir in $watch_dirs; do
        if [[ -d "$dir" ]]; then
            log "INFO" "Создание хэшей для $dir"
            
            # Формирование списка файлов, исключая паттерны
            find "$dir" -type f 2>/dev/null | grep -v -E "$exclude_grep" | \
            while read -r file; do
                # Создание хэша файла
                sha256sum "$file" >> "${SCRIPT_DIR}/hashes/baseline_$(echo "$dir" | tr '/' '_').txt"
            done
        else
            log "WARNING" "Директория $dir не найдена"
        fi
    done
    
    log "INFO" "Мониторинг целостности настроен"
}

# Проверка загрузки системы
check_system_load() {
    log "INFO" "Проверка загрузки системы..."
    
    # Получение текущей загрузки системы
    local load=$(cat /proc/loadavg | awk '{print $1}')
    local cpu_cores=$(nproc)
    local threshold=$(echo "$cpu_cores * 0.8" | bc)
    
    if (( $(echo "$load > $threshold" | bc -l) )); then
        log "WARNING" "Высокая загрузка системы: $load (порог: $threshold)"
        
        # Вывод топ-процессов по использованию CPU
        log "INFO" "Топ-5 процессов по использованию CPU:"
        ps -eo pid,%cpu,cmd --sort=-%cpu | head -6
    else
        log "INFO" "Загрузка системы в норме: $load"
    fi
    
    # Проверка использования памяти
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local mem_percent=$(echo "scale=2; $mem_used*100/$mem_total" | bc)
    
    if (( $(echo "$mem_percent > 90" | bc -l) )); then
        log "WARNING" "Критическое использование памяти: $mem_percent%"
        
        # Вывод топ-процессов по использованию памяти
        log "INFO" "Топ-5 процессов по использованию памяти:"
        ps -eo pid,%mem,cmd --sort=-%mem | head -6
    else
        log "INFO" "Использование памяти: $mem_percent%"
    fi
}

# Проверка подозрительных процессов
check_suspicious_processes() {
    log "INFO" "Проверка на подозрительные процессы..."
    
    # Получение списка подозрительных паттернов из конфигурации
    local suspicious_patterns=$(jq -r '.monitoring.processes.suspicious_patterns[]' "$CONFIG_FILE")
    local found_suspicious=0
    
    # Проверка каждого паттерна
    for pattern in $suspicious_patterns; do
        # Поиск процессов, соответствующих паттерну
        local procs=$(ps aux | grep -E "$pattern" | grep -v "grep")
        
        if [[ -n "$procs" ]]; then
            log "ALERT" "Обнаружен подозрительный процесс, соответствующий шаблону '$pattern':"
            echo "$procs" | while read -r proc; do
                log "WARNING" "$proc"
            done
            found_suspicious=1
        fi
    done
    
    # Проверка на процессы, запущенные из нестандартных мест
    local unusual_dirs=$(ps aux | grep -E "/tmp|/dev/shm|/var/tmp" | grep -v "grep")
    if [[ -n "$unusual_dirs" ]]; then
        log "ALERT" "Обнаружены процессы, запущенные из подозрительных директорий:"
        echo "$unusual_dirs" | while read -r proc; do
            log "WARNING" "$proc"
        done
        found_suspicious=1
    fi
    
    # Проверка на процессы, прослушивающие необычные порты
    local allowed_ports=$(jq -r '.monitoring.processes.allowed_ports[]' "$CONFIG_FILE")
    local unusual_ports=$(ss -tunlp | grep -v -E "127.0.0.1|::1" | grep -v -E ":($allowed_ports)\s")
    
    if [[ -n "$unusual_ports" ]]; then
        log "ALERT" "Обнаружены процессы, прослушивающие нестандартные порты:"
        echo "$unusual_ports" | while read -r port; do
            log "WARNING" "$port"
        done
        found_suspicious=1
    fi
    
    if [[ $found_suspicious -eq 0 ]]; then
        log "INFO" "Подозрительных процессов не обнаружено"
    else
        log "WARNING" "Обнаружены подозрительные процессы. Рекомендуется анализ."
    fi
}

# Проверка целостности системных файлов
check_system_integrity() {
    log "INFO" "Проверка целостности системных файлов..."
    
    local changed_files=0
    
    # Проверка, существуют ли базовые хэши
    if [[ ! -d "${SCRIPT_DIR}/hashes" ]]; then
        log "WARNING" "Директория с хэшами не найдена. Запустите setup_integrity_monitoring для создания."
        return 1
    fi
    
    # Проверка каждого файла хэшей
    for hash_file in "${SCRIPT_DIR}"/hashes/baseline_*.txt; do
        if [[ -f "$hash_file" ]]; then
            log "INFO" "Проверка хэшей из файла: $hash_file"
            
            # Временный файл для новых хэшей
            local temp_file=$(mktemp)
            
            # Для каждого файла в базовом хэше проверяем текущий хэш
            while read -r line; do
                local hash=$(echo "$line" | awk '{print $1}')
                local file=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
                
                if [[ -f "$file" ]]; then
                    # Вычисление нового хэша
                    local new_hash=$(sha256sum "$file" | awk '{print $1}')
                    
                    # Сравнение хэшей
                    if [[ "$hash" != "$new_hash" ]]; then
                        log "ALERT" "Файл изменен: $file"
                        log "INFO" "  Старый хэш: $hash"
                        log "INFO" "  Новый хэш: $new_hash"
                        ((changed_files++))
                    fi
                else
                    log "WARNING" "Файл отсутствует: $file"
                    ((changed_files++))
                fi
            done < "$hash_file"
            
            # Удаление временного файла
            rm -f "$temp_file"
        fi
    done
    
    if [[ $changed_files -eq 0 ]]; then
        log "INFO" "Все проверенные файлы сохранили целостность"
    else
        log "WARNING" "Обнаружено изменений: $changed_files"
    fi
}

# Анализ системных логов
analyze_system_logs() {
    log "INFO" "Анализ системных логов на наличие аномалий..."
    
    # Проверка логов аутентификации
    local auth_failures=0
    if [[ -f "/var/log/secure" ]]; then
        auth_failures=$(grep "Failed password" /var/log/secure | wc -l)
        if [[ $auth_failures -gt 10 ]]; then
            log "ALERT" "Обнаружено большое количество неудачных попыток аутентификации: $auth_failures"
            
            # Вывод топ-5 IP с неудачными попытками
            log "INFO" "Топ IP с неудачными попытками:"
            grep "Failed password" /var/log/secure | grep -o "from [0-9.]*" | sort | uniq -c | sort -nr | head -5
        fi
    fi
    
    # Проверка логов ssh
    if [[ -f "/var/log/secure" ]]; then
        local ssh_scan=$(grep "Did not receive identification string" /var/log/secure | wc -l)
        if [[ $ssh_scan -gt 5 ]]; then
            log "ALERT" "Обнаружены признаки сканирования SSH: $ssh_scan случаев"
        fi
    fi
    
    # Проверка логов системы
    if [[ -f "/var/log/messages" ]]; then
        # Проверка на ошибки ядра
        local kernel_errors=$(grep -i "kernel: \[ *[0-9.]*\] error" /var/log/messages | wc -l)
        if [[ $kernel_errors -gt 5 ]]; then
            log "WARNING" "Обнаружено много ошибок ядра: $kernel_errors"
        fi
        
        # Проверка на OOM killer
        if grep -q "Out of memory" /var/log/messages; then
            log "WARNING" "Обнаружено срабатывание OOM killer"
        fi
    fi
    
    # Проверка логов аудита
    if [[ -f "/var/log/audit/audit.log" ]]; then
        # Проверка на изменения в системных файлах
        local system_changes=$(grep -E "type=PATH.*key=\"(binary|user|sudo)_modification\"" /var/log/audit/audit.log | wc -l)
        if [[ $system_changes -gt 0 ]]; then
            log "ALERT" "Обнаружены изменения в критичных системных файлах: $system_changes"
        fi
    fi
}

# Проверка на признаки APT атак
check_for_apt_activity() {
    log "INFO" "Проверка на признаки APT активности..."
    
    local apt_indicators=0
    
    # Проверка на наличие странных CRON-задач
    if [[ -d "/var/spool/cron" ]]; then
        local suspicious_crons=$(find /var/spool/cron -type f -exec grep -l "wget\|curl\|nc\|bash -i" {} \; 2>/dev/null)
        if [[ -n "$suspicious_crons" ]]; then
            log "ALERT" "Обнаружены подозрительные CRON-задачи:"
            echo "$suspicious_crons" | while read -r cron; do
                log "WARNING" "Файл: $cron"
                cat "$cron"
            done
            ((apt_indicators++))
        fi
    fi
    
    # Проверка на скрытые файлы в домашних директориях
    local hidden_scripts=$(find /home -name ".*" -type f -not -path "*/\.*rc" -not -path "*/\.config/*" -not -path "*/\.cache/*" -exec grep -l "#!/bin/bash\|#!/bin/sh\|#!/usr/bin/env python" {} \; 2>/dev/null)
    if [[ -n "$hidden_scripts" ]]; then
        log "WARNING" "Обнаружены скрытые скрипты в домашних директориях:"
        echo "$hidden_scripts" | while read -r script; do
            log "WARNING" "Скрипт: $script"
        done
        ((apt_indicators++))
    fi
    
    # Проверка на нестандартные службы systemd
    local unusual_services=$(find /etc/systemd/system -type f -not -name "*.wants" -not -name "*.requires" | xargs grep -l "ExecStart=/tmp\|ExecStart=/var/tmp" 2>/dev/null)
    if [[ -n "$unusual_services" ]]; then
        log "ALERT" "Обнаружены подозрительные systemd службы:"
        echo "$unusual_services" | while read -r service; do
            log "WARNING" "Служба: $service"
            cat "$service"
        done
        ((apt_indicators++))
    fi
    
    # Проверка на модификацию файлов /etc/hosts
    if grep -q -v -E "^#|^127.0.0.1|^::1|^$" /etc/hosts; then
        log "WARNING" "Нестандартные записи в /etc/hosts:"
        grep -v -E "^#|^127.0.0.1|^::1|^$" /etc/hosts
        ((apt_indicators++))
    fi
    
    # Проверка на необычные разрешения SUID
    local unusual_suid=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm -4000 -not -path "/usr/bin/sudo" -not -path "/usr/bin/su" -not -path "/usr/bin/passwd" -not -path "/usr/bin/gpasswd" -not -path "/usr/bin/newgrp" -not -path "/usr/bin/chsh" -not -path "/usr/bin/chfn" 2>/dev/null)
    if [[ -n "$unusual_suid" ]]; then
        log "ALERT" "Обнаружены файлы с необычными разрешениями SUID:"
        echo "$unusual_suid" | while read -r suid_file; do
            log "WARNING" "Файл: $suid_file"
        done
        ((apt_indicators++))
    fi
    
    if [[ $apt_indicators -eq 0 ]]; then
        log "INFO" "Признаков APT активности не обнаружено"
    else
        log "WARNING" "Обнаружены признаки APT активности. Рекомендуется анализ."
    fi
}

harden_system() {
    log "INFO" "Executing system hardening steps..."
    # Add system hardening steps here
}

# Убедитесь, что все функции и блоки кода закрыты
# Например, если у вас есть незакрытая функция, добавьте закрывающую скобку:
#
# Если у вас есть незакрытый условный оператор, добавьте 'fi':
#
# Если у вас есть незакрытый цикл, добавьте 'done':
#