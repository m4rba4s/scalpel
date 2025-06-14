#!/bin/bash
#
# Утилиты для работы с системой обнаружения вторжений
# Часть системы защиты Fedora 41

# Инициализация IDS
initialize_ids() {
    log "INFO" "Инициализация системы обнаружения вторжений..."
    
    # Проверка наличия Suricata
    if ! command -v suricata &> /dev/null; then
        log "WARNING" "Suricata не установлена. IDS не будет работать."
        return 1
    fi
    
    # Получение пути к конфигурации из config.json
    local ids_config=$(jq -r '.network.ids.config_path' "$CONFIG_FILE")
    local custom_rules=$(jq -r '.network.ids.custom_rules' "$CONFIG_FILE")
    
    # Проверка существования конфигурационного файла
    if [[ ! -f "$ids_config" ]]; then
        log "WARNING" "Файл конфигурации Suricata не найден: $ids_config"
        return 1
    fi
    
    # Создание директории для правил, если она не существует
    local rules_dir=$(dirname "$custom_rules")
    mkdir -p "$rules_dir"
    
    # Если файл с кастомными правилами не существует, создаем его
    if [[ ! -f "$custom_rules" ]]; then
        log "INFO" "Создание файла с кастомными правилами: $custom_rules"
        
        # Добавление базовых правил
        cat > "$custom_rules" << EOF
# Кастомные правила Suricata для защиты Fedora 41
# Дата создания: $(date +"%Y-%m-%d %H:%M:%S")

# Правило для обнаружения сканирования портов
alert tcp any any -> \$HOME_NET any (msg:"PORT SCAN"; flags:S; threshold: type threshold, track by_src, count 30, seconds 60; classtype:attempted-recon; sid:10000001; rev:1;)

# Правило для обнаружения попыток брут-форса SSH
alert tcp any any -> \$HOME_NET 22 (msg:"BRUTE FORCE SSH"; flow:to_server; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:10000002; rev:1;)

# Правило для обнаружения команд shell в HTTP запросах
alert http any any -> \$HOME_NET any (msg:"SHELL COMMAND IN HTTP"; content:"cmd="; http_uri; pcre:"/cmd=.*(wget|curl|bash|nc|perl|python|sh)/Ui"; classtype:web-application-attack; sid:10000003; rev:1;)

# Правило для обнаружения попыток выполнения команд через SQL инъекции
alert http any any -> \$HOME_NET any (msg:"SQL INJECTION WITH COMMAND EXECUTION"; content:"EXEC"; nocase; pcre:"/EXEC(\s|\+)+(X|M)P\w+/i"; classtype:web-application-attack; sid:10000004; rev:1;)

# Правило для обнаружения попыток эксплойта Log4j
alert http any any -> \$HOME_NET any (msg:"LOG4J EXPLOITATION ATTEMPT"; content:"\${jndi:"; http_header; classtype:attempted-admin; sid:10000005; rev:1;)

# Правило для обнаружения обратных соединений
alert tcp \$HOME_NET any -> any !80,443,53,22,25,587 (msg:"POSSIBLE REVERSE SHELL"; flow:to_server,established; threshold: type threshold, track by_src, count 1, seconds 60; classtype:trojan-activity; sid:10000006; rev:1;)
EOF
    fi
    
    # Обновление правил Suricata (если используется suricata-update)
    if command -v suricata-update &> /dev/null; then
        log "INFO" "Обновление правил Suricata..."
        suricata-update
    fi
    
    # Проверка конфигурации Suricata
    log "INFO" "Проверка конфигурации Suricata..."
    suricata -T -c "$ids_config" -v
    
    # Если Suricata работает как служба, перезапускаем её
    if systemctl is-active suricata &>/dev/null; then
        log "INFO" "Перезапуск службы Suricata..."
        systemctl restart suricata
    else
        log "INFO" "Запуск Suricata в фоновом режиме..."
        suricata -c "$ids_config" -D
    fi
    
    log "INFO" "Инициализация IDS завершена"
}

# Функция анализа логов IDS
analyze_ids_logs() {
    log "INFO" "Анализ логов системы обнаружения вторжений..."
    
    # Получение пути к логам из config.json
    local ids_log_path=$(jq -r '.network.ids.log_path' "$CONFIG_FILE")
    
    # Проверка существования директории с логами
    if [[ ! -d "$ids_log_path" ]]; then
        log "WARNING" "Директория с логами Suricata не найдена: $ids_log_path"
        return 1
    fi
    
    # Проверка файла eve.json (основной лог Suricata)
    local eve_json="$ids_log_path/eve.json"
    if [[ ! -f "$eve_json" ]]; then
        log "WARNING" "Файл логов Suricata не найден: $eve_json"
        return 1
    fi
    
    # Анализ последних алертов
    log "INFO" "Анализ последних алертов IDS..."
    
    # Подсчет алертов за последний час
    local alerts_count=$(grep -c '"event_type":"alert"' "$eve_json")
    if [[ $alerts_count -gt 0 ]]; then
        log "WARNING" "Обнаружено $alerts_count алертов в системе IDS"
        
        # Вывод топ-5 алертов по типу
        log "INFO" "Топ-5 типов алертов:"
        grep '"event_type":"alert"' "$eve_json" | grep -o '"signature":"[^"]*"' | sort | uniq -c | sort -nr | head -5
        
        # Вывод топ-5 источников атак
        log "INFO" "Топ-5 источников атак:"
        grep '"event_type":"alert"' "$eve_json" | grep -o '"src_ip":"[^"]*"' | sort | uniq -c | sort -nr | head -5
        
        # Проверка на серьезные алерты
        local critical_alerts=$(grep '"event_type":"alert"' "$eve_json" | grep -E '"severity":[3-5]')
        if [[ -n "$critical_alerts" ]]; then
            log "ALERT" "Обнаружены критические алерты IDS!"
            
            # Если найдено более 5 критических алертов, можно активировать блокировку
            local critical_count=$(echo "$critical_alerts" | wc -l)
            if [[ $critical_count -gt 5 ]]; then
                log "CRITICAL" "Критическое количество серьезных алертов IDS: $critical_count!"
                
                # Здесь можно добавить автоматический вызов скрипта блокировки или уведомление
                # "${SCRIPT_DIR}/lockdown.sh"
            fi
        fi
    else
        log "INFO" "Алертов IDS не обнаружено"
    fi
}

setup_ids() {
    log "INFO" "Setting up Intrusion Detection System (IDS)..."
    # Add IDS setup steps here
} 