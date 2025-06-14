#!/bin/bash
#
# Утилиты для работы с сетью
# Часть системы защиты Fedora 41

# Функция настройки защиты сети
setup_network_protection() {
    log "INFO" "Настройка защиты сети..."
    
    # Настройка iptables/nftables
    if command -v nft &> /dev/null; then
        setup_nftables
    else
        setup_iptables
    fi
    
    # Отключение ненужных сетевых служб
    disable_network_services
    
    log "INFO" "Защита сети настроена"
}

# Настройка nftables
setup_nftables() {
    log "INFO" "Настройка nftables..."
    
    # Создание базового набора правил nftables
    nft flush ruleset
    
    # Основная таблица
    nft add table inet filter
    
    # Базовые цепочки
    nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
    nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
    
    # Разрешение установленных соединений
    nft add rule inet filter input ct state established,related accept
    
    # Разрешение localhost
    nft add rule inet filter input iifname "lo" accept
    
    # Разрешение ICMP (можно ограничить)
    nft add rule inet filter input ip protocol icmp icmp type echo-request limit rate 5/second accept
    
    # Разрешение SSH (опционально можно ограничить по IP)
    nft add rule inet filter input tcp dport 22 ct state new limit rate 5/minute accept
    
    log "INFO" "nftables настроен"
}

# Настройка iptables
setup_iptables() {
    log "INFO" "Настройка iptables..."
    
    # Сброс всех правил
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Установка дефолтной политики
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Разрешение установленных соединений
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # Разрешение localhost
    iptables -A INPUT -i lo -j ACCEPT
    
    # Разрешение ICMP (пинг) с ограничением скорости
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec -j ACCEPT
    
    # Разрешение SSH с ограничением попыток
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    
    # Логирование отброшенных пакетов
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
    
    log "INFO" "iptables настроен"
}

# Отключение ненужных сетевых служб
disable_network_services() {
    log "INFO" "Отключение ненужных сетевых служб..."
    
    # Список потенциально опасных или ненужных служб
    local services=(
        "rpcbind"
        "nfs-server"
        "rsh"
        "rlogin"
        "telnet"
        "tftp"
        "xinetd"
        "avahi-daemon"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active "$service" &>/dev/null; then
            log "INFO" "Остановка службы $service..."
            systemctl stop "$service"
            systemctl disable "$service"
        fi
    done
    
    log "INFO" "Ненужные сетевые службы отключены"
}

# Функция настройки анонимизации
setup_anonymization() {
    log "INFO" "Настройка анонимизации трафика..."
    
    # Проверка включена ли анонимизация в конфигурации
    local tor_enabled=$(jq -r '.network.tor.enabled' "$CONFIG_FILE")
    
    if [[ "$tor_enabled" == "true" ]]; then
        # Проверка установлен ли Tor
        if ! command -v tor &> /dev/null; then
            log "WARNING" "Tor не установлен. Анонимизация не может быть включена."
            return 1
        fi
        
        # Запуск Tor и настройка
        log "INFO" "Запуск Tor..."
        systemctl is-active tor &>/dev/null || systemctl start tor
        
        # Настройка transparent proxy, если включено
        local transparent_proxy=$(jq -r '.network.tor.transparent_proxy' "$CONFIG_FILE")
        if [[ "$transparent_proxy" == "true" ]]; then
            log "INFO" "Настройка прозрачного проксирования через Tor..."
            
            # Настройка iptables для перенаправления трафика через Tor
            iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner tor -j RETURN
            iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner tor -j RETURN
            iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9040
            iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9040
            
            log "INFO" "Прозрачное проксирование через Tor настроено"
        fi
        
        log "INFO" "Анонимизация через Tor настроена"
    else
        log "INFO" "Анонимизация через Tor отключена в конфигурации"
    fi
}

# Функция мониторинга трафика
monitor_traffic() {
    log "INFO" "Анализ сетевого трафика..."
    
    # Сбор статистики по сетевым соединениям
    local connections=$(ss -tunap)
    local foreign_connections=$(echo "$connections" | grep -v "127.0.0.1" | grep -v "::1")
    
    # Анализ подозрительных портов
    local allowed_ports=$(jq -r '.monitoring.processes.allowed_ports[]' "$CONFIG_FILE")
    local suspicious_connections=$(echo "$foreign_connections" | grep -v -E "dport=($allowed_ports)")
    
    if [[ -n "$suspicious_connections" ]]; then
        log "WARNING" "Обнаружены подозрительные сетевые соединения:"
        echo "$suspicious_connections" | while read -r conn; do
            log "WARNING" "$conn"
        done
    fi
    
    # Проверка на сканирование портов
    local port_scan_attempts=$(grep "iptables denied" /var/log/messages | wc -l)
    if [[ $port_scan_attempts -gt 10 ]]; then
        log "ALERT" "Возможное сканирование портов! Атаки: $port_scan_attempts за последний час"
    fi
    
    # Дополнительная проверка через tcpdump (опционально)
    if command -v tcpdump &> /dev/null; then
        local suspicious_packets=$(timeout 5 tcpdump -nn -c 100 2>/dev/null | grep -E 'S$|SF$' | wc -l)
        if [[ $suspicious_packets -gt 20 ]]; then
            log "WARNING" "Высокое количество SYN пакетов: возможная DDoS атака"
        fi
    fi
}

# Функция проверки подозрительных соединений
check_suspicious_connections() {
    local connections=$1
    local suspicious=0
    
    # Проверка на известные вредоносные IP (можно расширить или подключить списки)
    echo "$connections" | grep -E '185\.254\.121|45\.95\.168|185\.220\.' &>/dev/null && {
        log "ALERT" "Обнаружено соединение с известным вредоносным IP!"
        suspicious=1
    }
    
    # Проверка на необычные порты
    echo "$connections" | grep -E ':6666|:4444|:31337' &>/dev/null && {
        log "ALERT" "Обнаружено соединение с подозрительным портом!"
        suspicious=1
    }
    
    # Проверка на большое количество подключений с одного IP
    local top_connection=$(echo "$connections" | awk '{print $5}' | sort | uniq -c | sort -nr | head -1)
    local count=$(echo "$top_connection" | awk '{print $1}')
    local ip=$(echo "$top_connection" | awk '{print $2}')
    
    if [[ $count -gt 15 ]]; then
        log "WARNING" "Подозрительное количество соединений ($count) с IP: $ip"
        suspicious=1
    fi
    
    [[ $suspicious -eq 1 ]] && return 0 || return 1
}

secure_network() {
    log "INFO" "Executing network security configurations..."
    # Add network security configurations here
} 