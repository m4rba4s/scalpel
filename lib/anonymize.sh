#!/bin/bash
#
# Утилиты для анонимизации трафика
# Часть системы защиты Fedora 41

# Проверка доступности Tor
check_tor_availability() {
    if ! command -v tor &> /dev/null; then
        log "WARNING" "Tor не установлен. Анонимизация не может быть включена."
        return 1
    fi
    
    # Проверка работоспособности службы Tor
    if ! systemctl is-active tor &>/dev/null; then
        log "WARNING" "Служба Tor не запущена. Попытка запуска..."
        systemctl start tor
        
        # Проверка успешного запуска
        if ! systemctl is-active tor &>/dev/null; then
            log "ERROR" "Не удалось запустить службу Tor"
            return 1
        fi
    fi
    
    log "INFO" "Tor доступен и готов к использованию"
    return 0
}

# Настройка анонимизации через Tor
setup_tor_anonymization() {
    log "INFO" "Настройка анонимизации через Tor..."
    
    # Проверка доступности Tor
    if ! check_tor_availability; then
        return 1
    fi
    
    # Настройка прозрачного проксирования через Tor
    local transparent_proxy=$(jq -r '.network.tor.transparent_proxy' "$CONFIG_FILE")
    if [[ "$transparent_proxy" == "true" ]]; then
        log "INFO" "Настройка прозрачного проксирования через Tor..."
        
        # Сохранение текущих правил iptables
        iptables-save > "${SCRIPT_DIR}/backup/iptables_backup_$(date +%Y%m%d_%H%M%S).rules"
        
        # Настройка правил для перенаправления через Tor
        # Убедимся, что таблица nat существует
        iptables -t nat -L > /dev/null 2>&1
        
        # Очистка предыдущих правил для Tor
        iptables -t nat -F OUTPUT
        
        # Tor работает как прокси SOCKS5 на порту 9050 по умолчанию
        # Исключаем трафик от самого Tor, чтобы избежать циклов
        iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner tor -j RETURN
        
        # Исключаем локальные адреса
        iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
        iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN
        iptables -t nat -A OUTPUT -d 10.0.0.0/8 -j RETURN
        iptables -t nat -A OUTPUT -d 172.16.0.0/12 -j RETURN
        
        # Перенаправляем весь исходящий TCP-трафик через Tor
        iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 9040
        iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 9040
        
        log "INFO" "Прозрачное проксирование через Tor настроено"
    else
        log "INFO" "Прозрачное проксирование через Tor отключено в конфигурации"
    fi
    
    return 0
}

# Настройка VPN-соединения
setup_vpn() {
    log "INFO" "Настройка VPN-соединения..."
    
    # Проверка наличия OpenVPN
    if ! command -v openvpn &> /dev/null; then
        log "WARNING" "OpenVPN не установлен. VPN не может быть настроен."
        return 1
    fi
    
    # Проверка наличия конфигурационного файла
    local vpn_config="${SCRIPT_DIR}/config/vpn.ovpn"
    if [[ ! -f "$vpn_config" ]]; then
        log "WARNING" "Конфигурационный файл VPN не найден: $vpn_config"
        return 1
    fi
    
    # Запуск OpenVPN
    log "INFO" "Запуск OpenVPN..."
    
    # Останавливаем текущие соединения, если они есть
    killall openvpn &>/dev/null || true
    
    # Запуск в фоновом режиме
    openvpn --config "$vpn_config" --daemon
    
    # Проверка успешного подключения
    sleep 5
    if ip addr | grep -q "tun0"; then
        log "INFO" "VPN соединение установлено"
        
        # Настройка маршрутизации через VPN
        ip route add default via $(ip addr show tun0 | grep -Po 'peer \K[\d.]+') dev tun0
        
        return 0
    else
        log "ERROR" "Не удалось установить VPN соединение"
        return 1
    fi
}

# Отключение VPN
disable_vpn() {
    log "INFO" "Отключение VPN..."
    
    # Останавливаем OpenVPN
    killall openvpn &>/dev/null || true
    
    # Проверка отключения
    if ! ip addr | grep -q "tun0"; then
        log "INFO" "VPN соединение отключено"
        return 0
    else
        log "WARNING" "Не удалось отключить VPN"
        return 1
    fi
}

# Отключение анонимизации
disable_anonymization() {
    log "INFO" "Отключение анонимизации..."
    
    # Отключение прозрачного проксирования через Tor
    log "INFO" "Отключение прозрачного проксирования через Tor..."
    
    # Очистка правил iptables для Tor
    iptables -t nat -F OUTPUT
    
    # Восстановление маршрутизации по умолчанию
    if ip addr | grep -q "tun0"; then
        disable_vpn
    fi
    
    log "INFO" "Анонимизация отключена"
    return 0
}

# Функция проверки анонимности соединения
check_anonymity() {
    log "INFO" "Проверка анонимности соединения..."
    
    # Получение внешнего IP
    local external_ip=$(curl -s https://ipinfo.io/ip)
    
    if [[ -z "$external_ip" ]]; then
        log "WARNING" "Не удалось определить внешний IP-адрес"
        return 1
    fi
    
    log "INFO" "Текущий внешний IP-адрес: $external_ip"
    
    # Проверка утечек DNS
    log "INFO" "Проверка утечек DNS..."
    
    # Делаем DNS-запрос и проверяем, откуда он исходит
    local dns_server=$(dig +short whoami.akamai.net @ns1.dnscrypt.ca)
    
    if [[ -z "$dns_server" ]]; then
        log "WARNING" "Не удалось выполнить проверку утечек DNS"
    else
        log "INFO" "DNS-запросы идут через: $dns_server"
        
        # Проверка соответствия DNS-сервера внешнему IP
        if [[ "$dns_server" != "$external_ip" ]]; then
            log "ALERT" "Обнаружена утечка DNS! DNS-запросы идут в обход прокси."
        else
            log "INFO" "Утечек DNS не обнаружено"
        fi
    fi
    
    # Проверка WebRTC утечек (для этого потребуется интеграция с браузером)
    # Эта функциональность более сложная и требует дополнительных инструментов
    
    return 0
}

apply_anonymization() {
    log "INFO" "Applying traffic anonymization..."
    # Add traffic anonymization steps here
} 