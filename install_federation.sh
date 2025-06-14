#!/bin/bash
#
# FEDORA 41 - СИСТЕМА КОМПЛЕКСНОЙ ЗАЩИТЫ
# Главный установочный скрипт
# Разработано для HP ProBook 460 G11

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

# Проверка прав root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Этот скрипт должен запускаться с правами root${RESET}"
    exit 1
fi

# Вывод баннера
echo -e "${GREEN}"
echo '███████╗███████╗██████╗░░█████╗░██████╗░░█████╗░░░██╗██╗░'
echo '██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗░██╔╝██║'
echo '█████╗░░█████╗░░██║░░██║██║░░██║██████╔╝███████║██╔╝░██║'
echo '██╔══╝░░██╔══╝░░██║░░██║██║░░██║██╔══██╗██╔══██║███████║'
echo '██║░░░░░███████╗██████╔╝╚█████╔╝██║░░██║██║░░██║╚════██║'
echo '╚═╝░░░░░╚══════╝╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░░░░░╚═╝'
echo -e "${RESET}"
echo -e "${YELLOW}СИСТЕМА БЕЗОПАСНОСТИ ХАКЕРСКОГО УРОВНЯ - УСТАНОВКА${RESET}"
echo -e "Разработано для Fedora 41 | HP ProBook 460 G11"
echo ""

# Определение директорий
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/federation"
CONFIG_DIR="/etc/federation"
LOG_DIR="/var/log/federation"
LIB_DIR="${INSTALL_DIR}/lib"
SYSTEMD_DIR="/etc/systemd/system"

# Шаг 1: Создание директорий
echo -e "${GREEN}[1/5] Создание директорий...${RESET}"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$LIB_DIR" \
         "$INSTALL_DIR/tools" "$LOG_DIR/alerts" "$LOG_DIR/forensic"

# Шаг 2: Установка базовых зависимостей
echo -e "${GREEN}[2/5] Установка базовых зависимостей...${RESET}"
dnf install -y curl jq nftables iptables fail2ban auditd

# Шаг 3: Создание минимального монитора
echo -e "${GREEN}[3/5] Создание скрипта мониторинга...${RESET}"
cat > "$INSTALL_DIR/monitor.sh" << 'EOF'
#!/bin/bash
#
# FEDORA 41 - СИСТЕМА МОНИТОРИНГА И ЗАЩИТЫ
# Минимальный скрипт мониторинга для тестирования

echo "============================================"
echo "   СИСТЕМА МОНИТОРИНГА FEDORA 41"
echo "============================================"
echo "Запуск: $(date)"
echo "Хост: $(hostname)"

# Проверка прав
if [[ $EUID -ne 0 ]]; then
    echo "ОШИБКА: Этот скрипт требует прав администратора"
    exit 1
fi

# Проверка системы
echo "Проверка системы..."
echo "- Загрузка ЦП: $(uptime | awk '{print $10 $11 $12}')"
echo "- Память: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "- Диск: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"

# Проверка сети
echo "Проверка сети..."
echo "- Активные соединения: $(ss -tun | grep ESTAB | wc -l)"
echo "- Открытые порты: $(ss -tulpn | grep LISTEN | wc -l)"

# Проверка логов
echo "Проверка логов..."
echo "- Последние ошибки:"
grep -i error /var/log/messages 2>/dev/null | tail -3 || echo "  Нет доступа к логам"

echo "============================================"
echo "Мониторинг завершен: $(date)"
echo "Для полной версии установите все компоненты"
echo "============================================"
EOF

chmod +x "$INSTALL_DIR/monitor.sh"

# Шаг 4: Создание systemd сервиса
echo -e "${GREEN}[4/5] Настройка systemd-сервиса...${RESET}"
cat > "$SYSTEMD_DIR/federation-monitor.service" << EOF
[Unit]
Description=Fedora 41 Security Monitoring System
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/monitor.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Шаг 5: Установка прав и запуск
echo -e "${GREEN}[5/5] Установка прав и завершение...${RESET}"
chmod 750 "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chmod 750 "$INSTALL_DIR/monitor.sh"
systemctl daemon-reload
systemctl enable federation-monitor.service

echo ""
echo -e "${GREEN}Установка успешно завершена!${RESET}"
echo "Для ручного запуска мониторинга: sudo $INSTALL_DIR/monitor.sh"
echo "Для автоматического запуска: sudo systemctl start federation-monitor.service"
echo ""
echo -e "${YELLOW}Вы хотите запустить мониторинг сейчас? (y/n)${RESET}"
read -r response
if [[ "$response" == "y" || "$response" == "Y" ]]; then
    systemctl start federation-monitor.service
    echo "Мониторинг запущен. Проверьте статус: systemctl status federation-monitor.service"
else
    echo "Для запуска мониторинга выполните: sudo systemctl start federation-monitor.service"
fi 