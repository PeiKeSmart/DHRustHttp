@echo off
echo 构建优化后的Release版本...
cargo build --release

if %errorlevel% neq 0 (
    echo 构建失败！
    exit /b 1
)

echo.
echo 原始文件大小：
powershell "Get-Item .\target\release\DHRustHttp.exe | Select-Object @{Name='SizeMB';Expression={[math]::Round($_.Length/1MB, 2)}} | Format-Table -HideTableHeaders"

echo.
echo 使用UPX压缩...
if exist ".\upx-5.0.2-win64\upx.exe" (
    .\upx-5.0.2-win64\upx.exe --best --lzma .\target\release\DHRustHttp.exe
) else (
    echo UPX未找到，正在下载...
    powershell "Invoke-WebRequest -Uri 'https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-win64.zip' -OutFile 'upx.zip'"
    powershell "Expand-Archive -Path 'upx.zip' -DestinationPath '.'"
    .\upx-5.0.2-win64\upx.exe --best --lzma .\target\release\DHRustHttp.exe
)

echo.
echo 压缩后文件大小：
powershell "Get-Item .\target\release\DHRustHttp.exe | Select-Object @{Name='SizeMB';Expression={[math]::Round($_.Length/1MB, 2)}}, @{Name='SizeKB';Expression={[math]::Round($_.Length/1KB, 0)}} | Format-Table -HideTableHeaders"

echo.
echo 验证压缩后的二进制文件...
.\target\release\DHRustHttp.exe --version

if %errorlevel% equ 0 (
    echo.
    echo ✅ Release版本构建和压缩完成！
    echo    可执行文件: .\target\release\DHRustHttp.exe
) else (
    echo ❌ 验证失败！
    exit /b 1
)