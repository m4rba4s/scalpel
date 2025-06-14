#!/bin/bash

# Определение цветов для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Файл для исправления
INSTALL_FILE="./install.sh"
BACKUP_FILE="./install.sh.bak.$(date +%s)"

echo -e "${BLUE}[*] Начинаю исправление here-document в install.sh${NC}"

# Проверка существования файла
if [ ! -f "$INSTALL_FILE" ]; then
    echo -e "${RED}[!] Файл $INSTALL_FILE не найден${NC}"
    exit 1
fi

# Создание резервной копии
cp "$INSTALL_FILE" "$BACKUP_FILE"
echo -e "${GREEN}[+] Создана резервная копия: $BACKUP_FILE${NC}"

# Проверка строки 2105
if [ "$(wc -l < "$INSTALL_FILE")" -lt 2105 ]; then
    echo -e "${RED}[!] Файл содержит меньше 2105 строк${NC}"
    exit 1
fi

# Исследуем строку 2105 и окружающие
echo -e "${BLUE}[*] Исследую строку 2105 и окружающие...${NC}"
sed -n '2100,2110p' "$INSTALL_FILE" | nl -v 2100

# Находим маркер EOF в строке 2105
EOF_MARKER=$(sed -n '2105p' "$INSTALL_FILE" | grep -oP "<<\s*\K[A-Za-z0-9_]+")

if [ -z "$EOF_MARKER" ]; then
    # Если точный маркер не найден, просто ищем любой here-document
    EOF_MARKER=$(sed -n '2100,2110p' "$INSTALL_FILE" | grep -oP "<<\s*\K[A-Za-z0-9_]+" | head -n 1)
    
    if [ -z "$EOF_MARKER" ]; then
        echo -e "${YELLOW}[!] Не удалось найти маркер EOF в указанном диапазоне${NC}"
        echo -e "${YELLOW}[!] Пробую общее решение - добавление EOF в конец файла${NC}"
        EOF_MARKER="EOF"
    fi
fi

echo -e "${GREEN}[+] Используемый маркер EOF: $EOF_MARKER${NC}"

# Добавляем маркер EOF в конец файла
echo "$EOF_MARKER" >> "$INSTALL_FILE"
echo -e "${GREEN}[+] Добавлен маркер $EOF_MARKER в конец файла${NC}"

# Проверяем синтаксис исправленного файла
echo -e "${BLUE}[*] Проверяю синтаксис исправленного файла...${NC}"
bash -n "$INSTALL_FILE"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Синтаксическая ошибка исправлена успешно!${NC}"
    echo -e "${GREEN}[+] Исправленный файл: $INSTALL_FILE${NC}"
    echo -e "${GREEN}[+] Резервная копия: $BACKUP_FILE${NC}"
else
    echo -e "${RED}[!] Исправление не помогло, пробую альтернативный метод...${NC}"
    
    # Восстанавливаем из резервной копии
    cp "$BACKUP_FILE" "$INSTALL_FILE"
    
    # Пробуем другой метод - вставляем EOF перед последней строкой
    TMP_FILE="/tmp/install.sh.tmp"
    head -n -1 "$INSTALL_FILE" > "$TMP_FILE"
    echo "EOF" >> "$TMP_FILE"
    tail -n 1 "$INSTALL_FILE" >> "$TMP_FILE"
    cp "$TMP_FILE" "$INSTALL_FILE"
    
    echo -e "${BLUE}[*] Проверяю альтернативное решение...${NC}"
    bash -n "$INSTALL_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Альтернативное решение сработало!${NC}"
    else
        echo -e "${RED}[!] Оба метода не сработали. Рекомендуется ручное исправление${NC}"
        cp "$BACKUP_FILE" "$INSTALL_FILE"  # Восстанавливаем оригинал
        
        # Предлагаем простое замещение всего файла
        echo -e "${YELLOW}[*] Предлагаю заменить файл полностью новой версией${NC}"
        read -p "Заменить файл новой версией? (y/n): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Создаем новый файл install.sh
            cat > "./install.sh.new" << 'EOF_NEW_INSTALL'
#!/bin/bash

# Профессиональный установщик для системы безопасности
# Версия: 1.0.0

# Определение цветов для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Глобальные переменные
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
LOG_FILE="/var/log/security_install.log"

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
        *)
            echo -e "${timestamp} - $message"
            ;;
    esac
    
    # Записываем в лог файл если он существует
    if [ -f "$LOG_FILE" ]; then
        echo "${timestamp} [$level] - $message" >> "$LOG_FILE"
    fi
}

# Функция для проверки root прав
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi
}

# Функция для загрузки библиотек
load_libraries() {
    log "INFO" "Загрузка библиотек..."
    
    if [ -f "${LIB_DIR}/system_utils.sh" ]; then
        source "${LIB_DIR}/system_utils.sh"
        log "INFO" "Загружена system_utils.sh"
    else
        log "ERROR" "system_utils.sh не найдена в ${LIB_DIR}"
        exit 1
    fi
    
    if [ -f "${LIB_DIR}/network_utils.sh" ]; then
        source "${LIB_DIR}/network_utils.sh"
        log "INFO" "Загружена network_utils.sh"
    else
        log "ERROR" "network_utils.sh не найдена в ${LIB_DIR}"
        exit 1
    fi
    
    if [ -f "${LIB_DIR}/ids_utils.sh" ]; then
        source "${LIB_DIR}/ids_utils.sh"
        log "INFO" "Загружена ids_utils.sh"
    else
        log "ERROR" "ids_utils.sh не найдена в ${LIB_DIR}"
        exit 1
    fi
    
    if [ -f "${LIB_DIR}/forensics.sh" ]; then
        source "${LIB_DIR}/forensics.sh"
        log "INFO" "Загружена forensics.sh"
    else
        log "ERROR" "forensics.sh не найдена в ${LIB_DIR}"
        exit 1
    fi
    
    if [ -f "${LIB_DIR}/anonymize.sh" ]; then
        source "${LIB_DIR}/anonymize.sh"
        log "INFO" "Загружена anonymize.sh"
    else
        log "ERROR" "anonymize.sh не найдена в ${LIB_DIR}"
        exit 1
    fi
    
    log "INFO" "Все библиотеки загружены успешно"
}

# Функция для настройки системы
setup_system() {
    log "INFO" "Настройка системы..."
    
    # Создание конфигурации sysctl
    cat << EOF > /etc/sysctl.d/99-security.conf
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
    sysctl -p /etc/sysctl.d/99-security.conf
    
    log "INFO" "Системные настройки применены"
}

# Функция для запуска компонентов
run_components() {
    log "INFO" "Запуск компонентов..."
    
    # Запуск hardening системы
    if type -t harden_system &>/dev/null; then
        harden_system
        log "INFO" "Система защищена"
    else
        log "WARN" "Функция harden_system не найдена"
    fi
    
    # Настройка сети
    if type -t secure_network &>/dev/null; then
        secure_network
        log "INFO" "Сеть защищена"
    else
        log "WARN" "Функция secure_network не найдена"
    fi
    
    # Настройка IDS
    if type -t setup_ids &>/dev/null; then
        setup_ids
        log "INFO" "IDS настроена"
    else
        log "WARN" "Функция setup_ids не найдена"
    fi
    
    # Настройка форензики
    if type -t setup_forensics &>/dev/null; then
        setup_forensics
        log "INFO" "Форензика настроена"
    else
        log "WARN" "Функция setup_forensics не найдена"
    fi
    
    # Настройка анонимизации
    if type -t apply_anonymization &>/dev/null; then
        apply_anonymization
        log "INFO" "Анонимизация настроена"
    else
        log "WARN" "Функция apply_anonymization не найдена"
    fi
    
    log "INFO" "Все компоненты запущены"
}

# Основная функция
main() {
    log "INFO" "Запуск установки системы безопасности"
    
    # Проверка на root
    check_root
    
    # Загрузка библиотек
    load_libraries
    
    # Настройка системы
    setup_system
    
    # Запуск компонентов
    run_components
    
    log "INFO" "Установка успешно завершена"
    echo -e "${GREEN}Установка успешно завершена!${NC}"
}

# Запуск основной функции
main
EOF_NEW_INSTALL
            
            # Заменяем старый файл новым
            mv "./install.sh.new" "$INSTALL_FILE"
            chmod +x "$INSTALL_FILE"
            
            echo -e "${GREEN}[+] Файл успешно заменен. Попробуйте запустить его снова.${NC}"
        else
            echo -e "${YELLOW}[*] Файл не был заменен. Оставлен оригинал.${NC}"
        fi
    fi
fi

echo -e "${BLUE}[*] Операция завершена${NC}"
exit 0 