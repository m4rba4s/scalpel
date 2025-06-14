#!/bin/bash
#
# FEDORA 41 - СИСТЕМА КОМПЛЕКСНОЙ ЗАЩИТЫ
# Минимальный скрипт для тестирования установки
# Разработано для HP ProBook 460 G11

# Проверка прав root
if [[ $EUID -ne 0 ]]; then
    echo "Этот скрипт должен запускаться с правами root"
    exit 1
fi

echo "===== Тестирование установки системы защиты Fedora 41 ====="

# Определение директорий
INSTALL_DIR="/opt/federation"
CONFIG_DIR="/etc/federation"
LOG_DIR="/var/log/federation"
LIB_DIR="${INSTALL_DIR}/lib"

# Создание базовых директорий
echo "Создание директорий..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$LIB_DIR"

# Создание тестового скрипта
echo "Создание тестового скрипта..."
cat > "$INSTALL_DIR/test.sh" << 'EOF'
#!/bin/bash
echo "Тестовый скрипт работает!"
hostname
uname -a
date
EOF

# Установка прав
chmod +x "$INSTALL_DIR/test.sh"

echo "===== Тестовая установка завершена успешно! ====="
echo "Для проверки запустите: sudo $INSTALL_DIR/test.sh" 