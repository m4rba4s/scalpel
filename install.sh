#!/bin/bash

# Профессиональный установщик для системы безопасности
# Версия: 1.5.0

# Режим строгой обработки ошибок
set -e

# Определение цветов для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Глобальные переменные
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
LOG_FILE="/var/log/security_install.log"

# Настройки
VERBOSE=0
FORCE=0
SKIP_NETWORK=0
SKIP_IDS=0
SKIP_FORENSICS=0
SKIP_ANONYMIZE=0

# Функция логирования
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message"
            ;;
        "ALERT")
            echo -e "${MAGENTA}[ALERT]${NC} ${timestamp} - $message"
            ;;
        *)
            echo -e "${timestamp} - $message"
            ;;
    esac
    
    # Записываем в лог файл
    if [ -d "$(dirname "$LOG_FILE")" ]; then
        echo "${timestamp} [${level}] - ${message}" >> "$LOG_FILE"
    fi
}

# Функция для проверки root прав
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi
}

# Функция для проверки зависимостей
check_dependencies() {
    log "INFO" "Проверка необходимых зависимостей..."
    
    # Список необходимых программ
    local dependencies=("curl" "iptables" "grep" "awk" "sed")
    local missing=()
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ "${#missing[@]}" -gt 0 ]; then
        log "WARN" "Отсутствуют следующие зависимости: ${missing[*]}"
        log "INFO" "Установка отсутствующих зависимостей..."
        
        if command -v dnf &> /dev/null; then
            dnf install -y "${missing[@]}"
        elif command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y "${missing[@]}"
        else
            log "ERROR" "Не удалось определить пакетный менеджер для установки зависимостей"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    else
        log "INFO" "Все зависимости установлены"
    fi
}

# Функция для загрузки библиотек
load_libraries() {
    log "INFO" "Загрузка библиотек..."
    
    local libraries=(
        "system_utils.sh" 
        "network_utils.sh" 
        "ids_utils.sh" 
        "forensics.sh" 
        "anonymize.sh"
    )
    
    for lib in "${libraries[@]}"; do
        if [ -f "${LIB_DIR}/${lib}" ]; then
            log "DEBUG" "Загрузка ${lib}..."
            source "${LIB_DIR}/${lib}"
            log "DEBUG" "${lib} загружена успешно"
        else
            log "ERROR" "Библиотека ${lib} не найдена в ${LIB_DIR}"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    done
    
    log "INFO" "Все библиотеки загружены успешно"
    
    # Проверка наличия необходимых функций
    local required_functions=(
        "harden_system"
        "secure_network"
        "setup_ids"
        "setup_forensics"
        "apply_anonymization"
    )
    
    local missing_functions=()
    
    for func in "${required_functions[@]}"; do
        if ! type -t "$func" >/dev/null; then
            missing_functions+=("$func")
        fi
    done
    
    if [ "${#missing_functions[@]}" -gt 0 ]; then
        log "ERROR" "Отсутствуют необходимые функции: ${missing_functions[*]}"
        log "ERROR" "Библиотеки загружены некорректно"
        if [ "$FORCE" -ne 1 ]; then
            exit 1
        fi
    fi
}

# Функция для настройки системы
setup_system() {
    log "INFO" "Настройка системы безопасности..."
    
    # Создание конфигурации sysctl
    log "INFO" "Создание конфигурации sysctl..."
    mkdir -p /etc/sysctl.d/
    
    cat > /etc/sysctl.d/99-security.conf << EOF
# Enhanced security settings for Fedora 41
# System protection parameters
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0

# Network protection
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    
    # Применяем настройки sysctl
    log "INFO" "Применение настроек sysctl..."
    sysctl -p /etc/sysctl.d/99-security.conf
    
    log "INFO" "Базовая настройка системы завершена"
}

# Функция для запуска защиты системы
harden_system_wrapper() {
    log "INFO" "Запуск процесса защиты системы..."
    
    if type -t harden_system >/dev/null; then
        log "INFO" "Вызов функции harden_system из system_utils.sh"
        harden_system
        if [ $? -eq 0 ]; then
            log "INFO" "Система успешно защищена"
        else
            log "ERROR" "Ошибка при защите системы"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    else
        log "ERROR" "Функция harden_system не найдена"
        if [ "$FORCE" -ne 1 ]; then
            exit 1
        fi
    fi
    
    # Проверка подозрительных процессов
    if type -t check_suspicious_processes >/dev/null; then
        log "INFO" "Проверка подозрительных процессов..."
        check_suspicious_processes
    else
        log "WARN" "Функция check_suspicious_processes не найдена"
    fi
}

# Функция для настройки сетевой безопасности
secure_network_wrapper() {
    if [ "$SKIP_NETWORK" -eq 1 ]; then
        log "INFO" "Настройка сетевой безопасности пропущена"
        return 0
    fi
    
    log "INFO" "Настройка сетевой безопасности..."
    
    if type -t secure_network >/dev/null; then
        secure_network
        if [ $? -eq 0 ]; then
            log "INFO" "Сетевая безопасность настроена успешно"
        else
            log "ERROR" "Ошибка при настройке сетевой безопасности"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    else
        log "ERROR" "Функция secure_network не найдена"
        if [ "$FORCE" -ne 1 ]; then
            exit 1
        fi
    fi
}

# Функция для настройки IDS
setup_ids_wrapper() {
    if [ "$SKIP_IDS" -eq 1 ]; then
        log "INFO" "Настройка IDS пропущена"
        return 0
    fi
    
    log "INFO" "Настройка системы обнаружения вторжений (IDS)..."
    
    if type -t setup_ids >/dev/null; then
        setup_ids
        if [ $? -eq 0 ]; then
            log "INFO" "IDS настроена успешно"
        else
            log "ERROR" "Ошибка при настройке IDS"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    else
        log "ERROR" "Функция setup_ids не найдена"
        if [ "$FORCE" -ne 1 ]; then
            exit 1
        fi
    fi
}

# Функция для настройки инструментов форензики
setup_forensics_wrapper() {
    if [ "$SKIP_FORENSICS" -eq 1 ]; then
        log "INFO" "Настройка инструментов форензики пропущена"
        return 0
    fi
    
    log "INFO" "Настройка инструментов форензики..."
    
    if type -t setup_forensics >/dev/null; then
        setup_forensics
        if [ $? -eq 0 ]; then
            log "INFO" "Инструменты форензики настроены успешно"
        else
            log "ERROR" "Ошибка при настройке инструментов форензики"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    else
        log "ERROR" "Функция setup_forensics не найдена"
        if [ "$FORCE" -ne 1 ]; then
            exit 1
        fi
    fi
}

# Функция для настройки анонимизации
apply_anonymization_wrapper() {
    if [ "$SKIP_ANONYMIZE" -eq 1 ]; then
        log "INFO" "Настройка анонимизации пропущена"
        return 0
    fi
    
    log "INFO" "Настройка анонимизации..."
    
    if type -t apply_anonymization >/dev/null; then
        apply_anonymization
        if [ $? -eq 0 ]; then
            log "INFO" "Анонимизация настроена успешно"
        else
            log "ERROR" "Ошибка при настройке анонимизации"
            if [ "$FORCE" -ne 1 ]; then
                exit 1
            fi
        fi
    else
        log "ERROR" "Функция apply_anonymization не найдена"
        if [ "$FORCE" -ne 1 ]; then
            exit 1
        fi
    fi
}

# Функция для очистки после установки
cleanup() {
    log "INFO" "Очистка после установки..."
    
    # Удаление временных файлов
    rm -rf /tmp/security_install_*
    
    log "INFO" "Очистка завершена"
}

# Функция помощи
show_help() {
    echo "Использование: $0 [ОПЦИИ]"
    echo ""
    echo "Опции:"
    echo "  -h, --help           Показать эту справку"
    echo "  -v, --verbose        Подробный вывод"
    echo "  -f, --force          Продолжать выполнение при ошибках"
    echo "  --skip-network       Пропустить настройку сети"
    echo "  --skip-ids           Пропустить настройку IDS"
    echo "  --skip-forensics     Пропустить настройку форензики"
    echo "  --skip-anonymize     Пропустить настройку анонимизации"
    echo ""
}

# Обработка аргументов командной строки
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                ;;
            -f|--force)
                FORCE=1
                ;;
            --skip-network)
                SKIP_NETWORK=1
                ;;
            --skip-ids)
                SKIP_IDS=1
                ;;
            --skip-forensics)
                SKIP_FORENSICS=1
                ;;
            --skip-anonymize)
                SKIP_ANONYMIZE=1
                ;;
            *)
                echo "Неизвестный параметр: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

# Главная функция
main() {
    # Создаем директорию для лога
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Баннер
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                FEDORA 41 SECURITY HARDENING                    ║"
    echo "║                   ELITE PROTECTION SYSTEM                      ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "INFO" "Запуск установки системы безопасности"
    
    # Проверка root прав
    check_root
    
    # Проверка зависимостей
    check_dependencies
    
    # Загрузка библиотек
    load_libraries
    
    # Настройка системы
    setup_system
    
    # Защита системы
    harden_system_wrapper
    
    # Настройка сетевой безопасности
    secure_network_wrapper
    
    # Настройка IDS
    setup_ids_wrapper
    
    # Настройка форензики
    setup_forensics_wrapper
    
    # Настройка анонимизации
    apply_anonymization_wrapper
    
    # Очистка
    cleanup
    
    log "INFO" "Установка системы безопасности завершена успешно"
    echo -e "\n${GREEN}${BOLD}Установка успешно завершена!${NC}"
    echo -e "Лог установки доступен в файле: ${LOG_FILE}"
}

# Парсинг аргументов
parse_args "$@"

# Запуск главной функции
main
