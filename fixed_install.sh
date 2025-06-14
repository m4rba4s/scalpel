#!/bin/bash
#
# FEDORA 41 - СИСТЕМА КОМПЛЕКСНОЙ ЗАЩИТЫ
# Скрипт автоматической установки
# Разработано для HP ProBook 460 G11

# Установка строгого режима bash
set -euo pipefail
IFS=$'\n\t'

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Функция вывода баннера
show_banner() {
    echo -e "${MAGENTA}"
    echo '███████╗███████╗██████╗░░█████╗░██████╗░░█████╗░░░██╗██╗░███╗░░'
    echo '██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗░██╔╝██║████║░░'
    echo '█████╗░░█████╗░░██║░░██║██║░░██║██████╔╝███████║██╔╝░██║██╔██╗░'
    echo '██╔══╝░░██╔══╝░░██║░░██║██║░░██║██╔══██╗██╔══██║███████║██║╚██╗'
    echo '██║░░░░░███████╗██████╔╝╚█████╔╝██║░░██║██║░░██║╚════██║██║░╚██╗'
    echo '╚═╝░░░░░╚══════╝╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░░░░░╚═╝╚═╝░░╚═╝'
    echo -e "${CYAN}    СИСТЕМА БЕЗОПАСНОСТИ ХАКЕРСКОГО УРОВНЯ ${RESET}"
    echo -e "${YELLOW}    Разработано для Fedora 41 | HP ProBook 460 G11 ${RESET}"
    echo ""
}

# Определение директорий установки
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/federation"
CONFIG_DIR="/etc/federation"
LOG_DIR="/var/log/federation"
LIB_DIR="${INSTALL_DIR}/lib"
BACKUP_DIR="${INSTALL_DIR}/backup"
RULES_DIR="${CONFIG_DIR}/rules"
SYSTEMD_DIR="/etc/systemd/system"
COMPLETION_DIR="/etc/bash_completion.d"

# Функция для вывода сообщений
log() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${RESET} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${RESET} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${RESET} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${RESET} $message"
            ;;
        *)
            echo -e "[$level] $message"
            ;;
    esac
}

# Функция проверки прав root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Этот скрипт должен запускаться с правами root"
        exit 1
    fi
    
    log "INFO" "Права администратора подтверждены"
}

# Функция проверки ОС
check_os() {
    log "INFO" "Проверка операционной системы..."
    
    if [[ -f /etc/fedora-release ]]; then
        local fedora_version=$(cat /etc/fedora-release | grep -oP '(?<=release )[0-9]+')
        log "INFO" "Обнаружена Fedora $fedora_version"
        
        if [[ "$fedora_version" -lt 41 ]]; then
            log "WARNING" "Рекомендуется использовать Fedora 41 или выше. Текущая версия: $fedora_version"
            
            echo -e "${YELLOW}Продолжить установку на Fedora $fedora_version? (y/n)${RESET}"
            read -r response
            if [[ "$response" != "y" && "$response" != "Y" ]]; then
                log "ERROR" "Установка отменена пользователем"
                exit 1
            fi
        fi
    else
        log "WARNING" "Система не определена как Fedora. Некоторые функции могут работать некорректно."
        
        echo -e "${YELLOW}Продолжить установку на неподдерживаемой ОС? (y/n)${RESET}"
        read -r response
        if [[ "$response" != "y" && "$response" != "Y" ]]; then
            log "ERROR" "Установка отменена пользователем"
            exit 1
        fi
    fi
    
    log "SUCCESS" "Проверка ОС завершена"
}

# Функция проверки оборудования
check_hardware() {
    log "INFO" "Проверка оборудования..."
    
    # Проверка модели ноутбука, если это HP ProBook
    if command -v dmidecode &> /dev/null; then
        local system_product=$(dmidecode -s system-product-name)
        if [[ "$system_product" == *"HP ProBook"* ]]; then
            log "INFO" "Обнаружен HP ProBook: $system_product"
        else
            log "WARNING" "Система оптимизирована для HP ProBook 460 G11. Текущее оборудование: $system_product"
        fi
    fi
    
    # Проверка минимальных требований
    local cpu_cores=$(nproc)
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local disk_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    log "INFO" "Доступно ядер CPU: $cpu_cores"
    log "INFO" "Доступно оперативной памяти: $mem_total MB"
    log "INFO" "Доступно места на диске: $disk_space GB"
    
    if [[ $cpu_cores -lt 2 ]]; then
        log "WARNING" "Рекомендуется минимум 2 ядра CPU"
    fi
    
    if [[ $mem_total -lt 2048 ]]; then
        log "WARNING" "Рекомендуется минимум 2 GB RAM"
    fi
    
    if [[ $disk_space -lt 5 ]]; then
        log "WARNING" "Рекомендуется минимум 5 GB свободного места"
    fi
    
    log "SUCCESS" "Проверка оборудования завершена"
}

# Функция установки зависимостей
install_dependencies() {
    log "INFO" "Установка зависимостей..."
    
    local deps=(
        "nftables" "iptables" "suricata" "tor" "proxychains" "fail2ban" 
        "firejail" "curl" "jq" "fzf" "tcpdump" "auditd" "dmidecode" 
        "openssl" "lsof" "net-tools" "psmisc" "sysstat" "htop" "chrony"
        "chkrootkit" "rkhunter" "lynis" "aide" "clamav" "clamav-update"
    )
    
    # Обновление списка пакетов
    log "INFO" "Обновление репозиториев..."
    dnf check-update -y || true
    
    # Установка основных зависимостей
    log "INFO" "Установка основных пакетов..."
    local failed_deps=()
    
    for dep in "${deps[@]}"; do
        log "INFO" "Установка пакета: $dep"
        if ! dnf install -y "$dep"; then
            failed_deps+=("$dep")
            log "WARNING" "Не удалось установить пакет: $dep"
        fi
    done
    
    # Проверка неудачных установок
    if [[ ${#failed_deps[@]} -gt 0 ]]; then
        log "WARNING" "Не удалось установить следующие пакеты: ${failed_deps[*]}"
        
        echo -e "${YELLOW}Некоторые пакеты не удалось установить. Продолжить установку? (y/n)${RESET}"
        read -r response
        if [[ "$response" != "y" && "$response" != "Y" ]]; then
            log "ERROR" "Установка отменена пользователем"
            exit 1
        fi
    fi
    
    # Дополнительные настройки установленных пакетов
    log "INFO" "Настройка установленных пакетов..."
    
    # Настройка Suricata
    if command -v suricata &> /dev/null; then
        log "INFO" "Настройка Suricata..."
        # Обновление правил, если доступно
        if command -v suricata-update &> /dev/null; then
            suricata-update
        fi
    fi
    
    # Настройка ClamAV
    if command -v freshclam &> /dev/null; then
        log "INFO" "Обновление баз данных ClamAV..."
        systemctl stop clamav-freshclam || true
        freshclam
        systemctl start clamav-freshclam || true
    fi
    
    # Настройка AIDE
    if command -v aide &> /dev/null; then
        log "INFO" "Инициализация базы данных AIDE..."
        aide --init || true
        if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        fi
    fi
    
    # Настройка fail2ban
    if command -v fail2ban-client &> /dev/null; then
        log "INFO" "Настройка fail2ban..."
        systemctl enable fail2ban
    fi
    
    # Настройка auditd
    if command -v auditctl &> /dev/null; then
        log "INFO" "Настройка системы аудита..."
        systemctl enable auditd
    fi
    
    log "SUCCESS" "Зависимости установлены и настроены"
}

# Функция создания директорий
create_directories() {
    log "INFO" "Создание директорий..."
    
    # Создание основных директорий
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$LIB_DIR" \
             "$BACKUP_DIR" "$RULES_DIR" "$LOG_DIR/forensic" \
             "$INSTALL_DIR/tools" "$CONFIG_DIR/templates"
    
    # Создание дополнительных директорий
    mkdir -p "$LOG_DIR/ids" "$LOG_DIR/alerts" "$BACKUP_DIR/config" \
             "$BACKUP_DIR/logs" "$INSTALL_DIR/hashes"
    
    log "SUCCESS" "Директории созданы"
}

# Функция создания файлов
create_files() {
    log "INFO" "Создание файлов скриптов и конфигурации..."
    
    # 1. Создание monitor.sh
    cat > "$INSTALL_DIR/monitor.sh" << 'EOF'
#!/bin/bash
#
# FEDORA 41 - СИСТЕМА МОНИТОРИНГА И ЗАЩИТЫ
# Основной скрипт мониторинга
# Разработано для HP ProBook 460 G11

# Настройка строгого режима bash
set -euo pipefail
IFS=$'\n\t'

# Глобальные переменные
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="/etc/federation/config.json"
LOG_FILE="/var/log/federation/monitor.log"
ALERT_LOG="/var/log/federation/alerts/alerts.log"
CURRENT_TIME="$(date +"%Y-%m-%d %H:%M:%S")"
VERSION="1.0.0"

# Подключение библиотек
source "${SCRIPT_DIR}/lib/network_utils.sh"
source "${SCRIPT_DIR}/lib/system_utils.sh"
source "${SCRIPT_DIR}/lib/ids_utils.sh"
source "${SCRIPT_DIR}/lib/forensics.sh"
source "${SCRIPT_DIR}/lib/anonymize.sh"

# Функция вывода баннера
show_banner() {
    echo -e "\e[1;31m"
    echo '███████╗███████╗██████╗ ███████╗██████╗  █████╗  ██╗  ██╗ ██╗'
    echo '██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗ ██║  ██║███║'
    echo '█████╗  █████╗  ██║  ██║█████╗  ██████╔╝███████║ ███████║╚██║'
    echo '██╔══╝  ██╔══╝  ██║  ██║██╔══╝  ██╔══██╗██╔══██║ ╚════██║ ██║'
    echo '██║     ███████╗██████╔╝███████╗██║  ██║██║  ██║      ██║ ██║'
    echo '╚═╝     ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═╝ ╚═╝'
    echo -e "\e[1;34m    ADVANCED SECURITY MONITORING SYSTEM v${VERSION}\e[0m"
    echo -e "\e[1;33m    Разработано для Fedora 41 | HP ProBook 460 G11\e[0m"
    echo ""
}

# Функция логирования
log() {
    local level=$1
    local message=$2
    local current_time="$(date +"%Y-%m-%d %H:%M:%S")"
    
    # Создаем директорию для логов, если она не существует
    mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$ALERT_LOG")"
    
    echo -e "[$current_time] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO") echo -e "\e[1;32m[INFO]\e[0m $message" ;;
        "WARNING") echo -e "\e[1;33m[WARNING]\e[0m $message" ;;
        "ERROR") echo -e "\e[1;31m[ERROR]\e[0m $message" ;;
        "ALERT") 
            echo -e "\e[1;37;41m[ALERT]\e[0m $message"
            echo "[$current_time] [ALERT] $message" >> "$ALERT_LOG"
            ;;
        *) echo -e "[$level] $message" ;;
    esac
}

# Функция проверки зависимостей
check_dependencies() {
    log "INFO" "Проверка зависимостей..."
    local deps=(nft iptables suricata tor proxychains fail2ban firejail curl jq fzf netstat auditctl)
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log "ERROR" "Отсутствуют следующие зависимости: ${missing[*]}"
        log "INFO" "Установите их командой: sudo dnf install ${missing[*]}"
        exit 1
    fi
    
    log "INFO" "Все зависимости установлены"
}

# Функция инициализации системы
initialize_system() {
    log "INFO" "Инициализация системы защиты..."
    
    # Создание директорий для логов
    mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$ALERT_LOG")"
    
    # Настройка прав доступа
    chmod 750 "$(dirname "$LOG_FILE")"
    chmod 640 "$LOG_FILE" "$ALERT_LOG"
    
    # Загрузка конфигурации
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Загрузка конфигурации из $CONFIG_FILE"
    else
        log "ERROR" "Конфигурационный файл не найден: $CONFIG_FILE"
        exit 1
    fi
    
    # Инициализация IDS
    initialize_ids
    
    # Настройка анонимизации
    setup_anonymization
    
    # Настройка сетевых правил
    setup_network_protection
    
    # Настройка системного мониторинга
    setup_system_monitoring
    
    log "INFO" "Система инициализирована"
}

# Функция мониторинга сети
monitor_network() {
    log "INFO" "Запуск мониторинга сети..."
    
    # Анализ текущих соединений
    local connections=$(ss -tunap | grep -v "127.0.0.1")
    local connection_count=$(echo "$connections" | wc -l)
    
    log "INFO" "Активных внешних соединений: $connection_count"
    
    # Проверка на подозрительные соединения
    check_suspicious_connections "$connections"
    
    # Мониторинг сетевого трафика
    monitor_traffic
}

# Функция мониторинга системы
monitor_system() {
    log "INFO" "Запуск мониторинга системы..."
    
    # Проверка загрузки системы
    check_system_load
    
    # Проверка необычных процессов
    check_suspicious_processes
    
    # Проверка целостности системных файлов
    check_system_integrity
    
    # Проверка логов на подозрительную активность
    analyze_system_logs
}

# Главная функция
main() {
    # Вывод баннера
    show_banner
    
    # Проверка прав администратора
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Этот скрипт должен запускаться с правами root"
        exit 1
    fi
    
    # Проверка зависимостей
    check_dependencies
    
    # Инициализация системы
    initialize_system
    
    log "INFO" "Система мониторинга запущена"
    
    # Основной цикл мониторинга
    while true; do
        monitor_network
        monitor_system
        
        # Проверка на признаки APT-атак
        check_for_apt_activity
        
        # Периодический анализ логов IDS
        analyze_ids_logs
        
        # Интервал проверки из конфигурации
        local check_interval=$(jq -r '.system.check_interval // 60' "$CONFIG_FILE")
        log "INFO" "Ожидание $check_interval секунд до следующей проверки"
        sleep "$check_interval"
    done
}

# Запуск программы
main "$@"
EOF

    # 2. Создание lockdown.sh
    cat > "$INSTALL_DIR/lockdown.sh" << 'EOF'
#!/bin/bash
#
# FEDORA 41 - СИСТЕМА МОНИТОРИНГА И ЗАЩИТЫ
# Скрипт экстренной блокировки системы
# Разработано для HP ProBook 460 G11

# Настройка строгого режима bash
set -euo pipefail
IFS=$'\n\t'

# Глобальные переменные
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="/etc/federation/config.json"
LOG_FILE="/var/log/federation/lockdown.log"
FORENSIC_DIR="/var/log/federation/forensic/$(date +%Y%m%d_%H%M%S)"
CURRENT_TIME="$(date +"%Y-%m-%d %H:%M:%S")"

# Подключение библиотек
source "${SCRIPT_DIR}/lib/network_utils.sh"
source "${SCRIPT_DIR}/lib/system_utils.sh"
source "${SCRIPT_DIR}/lib/forensics.sh"

# Функция вывода баннера
show_banner() {
    echo -e "\e[1;37;41m"
    echo '██       ██████   ██████ ██   ██ ██████   ██████  ██     ██ ███    ██'
    echo '██      ██    ██ ██     ██  ██  ██   ██ ██    ██ ██     ██ ████   ██'
    echo '██      ██    ██ ██     █████   ██   ██ ██    ██ ██  █  ██ ██ ██  ██'
    echo '██      ██    ██ ██     ██  ██  ██   ██ ██    ██ ██ ███ ██ ██  ██ ██'
    echo '███████  ██████   ██████ ██   ██ ██████   ██████   ███ ███  ██   ████'
    echo -e "\e[1;31m        ЭКСТРЕННЫЙ РЕЖИМ ИЗОЛЯЦИИ СИСТЕМЫ        \e[0m"
    echo -e "\e[1;33m        Разработано для Fedora 41 | HP ProBook 460 G11\e[0m"
    echo ""
}

# Функция логирования
log() {
    local level=$1
    local message=$2
    local current_time="$(date +"%Y-%m-%d %H:%M:%S")"
    
    # Создаем директорию для логов, если она не существует
    mkdir -p "$(dirname "$LOG_FILE")"
    
    echo -e "[$current_time] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO") echo -e "\e[1;32m[INFO]\e[0m $message" ;;
        "WARNING") echo -e "\e[1;33m[WARNING]\e[0m $message" ;;
        "ERROR") echo -e "\e[1;31m[ERROR]\e[0m $message" ;;
        "ALERT") echo -e "\e[1;37;41m[ALERT]\e[0m $message" ;;
        "CRITICAL") echo -e "\e[1;37;41m[КРИТИЧНО]\e[0m $message" ;;
        *) echo -e "[$level] $message" ;;
    esac
}

# Функция создания снапшота системы для форензики
create_system_snapshot() {
    log "INFO" "Создание снапшота системы для анализа..."
    
    # Создание директории для форензики
    mkdir -p "$FORENSIC_DIR"
    
    # Сохранение информации о системе
    uname -a > "$FORENSIC_DIR/system_info.txt"
    
    # Сохранение списка процессов
    ps auxf > "$FORENSIC_DIR/processes.txt"
    
    # Сохранение списка соединений
    ss -tunap > "$FORENSIC_DIR/connections.txt"
    
    # Сохранение загруженных модулей ядра
    lsmod > "$FORENSIC_DIR/kernel_modules.txt"
    
    # Сохранение открытых файлов
    lsof > "$FORENSIC_DIR/open_files.txt"
    
    # Сохранение содержимого системных логов
    cp /var/log/messages "$FORENSIC_DIR/" 2>/dev/null || true
    cp /var/log/secure "$FORENSIC_DIR/" 2>/dev/null || true
    cp /var/log/audit/audit.log "$FORENSIC_DIR/" 2>/dev/null || true
    
    # Сохранение информации о дисках
    df -h > "$FORENSIC_DIR/disk_usage.txt"
    
    # Сохранение таблиц маршрутизации
    ip route > "$FORENSIC_DIR/routes.txt"
    
    # Сохранение правил iptables
    iptables-save > "$FORENSIC_DIR/iptables.txt"
    
    # Сохранение содержимого /tmp
    find /tmp -type f -exec ls -la {} \; > "$FORENSIC_DIR/tmp_files.txt" 2>/dev/null || true
    
    # Создание хэш-сумм важных системных файлов
    find /bin /sbin /usr/bin /usr/sbin -type f -exec sha256sum {} \; > "$FORENSIC_DIR/system_binaries_hash.txt" 2>/dev/null || true
    
    log "INFO" "Снапшот системы создан в $FORENSIC_DIR"
}

# Функция отключения сетевых интерфейсов
disable_network() {
    log "CRITICAL" "Отключение всех сетевых интерфейсов..."
    
    # Сохранение текущего сетевого состояния
    ip addr > "$FORENSIC_DIR/network_before_lockdown.txt"
    
    # Отключение всех физических сетевых интерфейсов
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
        log "INFO" "Отключение интерфейса $iface"
        ip link set "$iface" down
    done
    
    # Блокировка всех беспроводных интерфейсов с помощью rfkill
    if command -v rfkill &> /dev/null; then
        rfkill block all
        log "INFO" "Все беспроводные интерфейсы заблокированы"
    fi
    
    # Блокировка всех входящих и исходящих соединений с помощью iptables
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    
    # Сохранение только соединений localhost
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    log "INFO" "Все сетевые интерфейсы отключены и заблокированы"
}

# Функция завершения подозрительных процессов
terminate_suspicious_processes() {
    log "WARNING" "Идентификация и завершение подозрительных процессов..."
    
    # Список потенциально вредоносных процессов (шаблон)
    suspicious_procs=(
        "nc -"
        "ncat -"
        "netcat"
        "miner"
        "\.sh$"
        "\.py$"
        "python3 -"
        "bash -i"
        "perl -e"
        "ruby -e"
        "wget http"
        "curl http"
    )
    
    # Поиск и завершение подозрительных процессов
    for pattern in "${suspicious_procs[@]}"; do
        pids=$(ps aux | grep -E "$pattern" | grep -v "grep" | awk '{print $2}')
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                cmd=$(ps -p "$pid" -o cmd=)
                log "WARNING" "Завершение подозрительного процесса: $pid ($cmd)"
                kill -9 "$pid" 2>/dev/null || true
            done
        fi
    done
    
    log "INFO" "Завершение процессов выполнено"
}

# Функция шифрования критичных данных
encrypt_critical_data() {
    log "INFO" "Шифрование критичных данных..."
    
    # Проверяем наличие критичных данных
    critical_dirs=("/home/$(whoami)/sensitive" "/root/sensitive" "/opt/secure")
    
    for dir in "${critical_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log "INFO" "Шифрование директории $dir"
            
            # Создание архива, зашифрованного с помощью OpenSSL
            archive_name="${FORENSIC_DIR}/$(basename "$dir")_$(date +%Y%m%d_%H%M%S).enc"
            tar -czf - "$dir" 2>/dev/null | openssl enc -
        fi
    done
}
EOF
} 