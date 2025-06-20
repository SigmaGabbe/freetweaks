@echo off
:: Require admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Please run this batch file as Administrator.
    pause
    exit /b
)

echo Applying visual settings...

:: Adjust for best performance (disables most effects)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f

:: Disable specific effects (set in UserPreferencesMask)
:: The following mask is a common setting for best performance. You may need to fine-tune.
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012008010000000 /f

:: Disable window animations
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f

:: Set desktop background to solid black
reg add "HKCU\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f

:: Disable transparency effects (for accessibility - this disables acrylic blur)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f

echo Visual settings applied. You may need to sign out and sign in or reboot for all changes to take effect.
pause
