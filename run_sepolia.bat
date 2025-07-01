@echo off
chcp 65001 >nul
echo 正在启动Sepolia测试网代币领取工具...
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请先安装Python 3.6或更高版本
    pause
    exit /b 1
)

REM 检查依赖是否安装
echo 检查依赖包...
pip show web3 >nul 2>&1
if errorlevel 1 (
    echo 正在安装依赖包...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo 错误: 依赖包安装失败
        pause
        exit /b 1
    )
)

echo.
echo ================================
echo Sepolia测试网代币领取工具
echo 合约地址: 0x3edf60dd017ace33a0220f78741b5581c385a1ba
echo 网络: Sepolia测试网
echo ================================
echo.
echo 启动程序...
python sepolia_claimer.py

if errorlevel 1 (
    echo.
    echo 程序异常退出，按任意键关闭窗口
    pause >nul
) 