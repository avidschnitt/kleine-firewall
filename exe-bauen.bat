@echo off
rem Baut KleineFirewall.exe (einmalig Python von python.org noetig)
python -m pip install pyinstaller || goto :fehler
python -m PyInstaller --onefile --noconsole --uac-admin --name KleineFirewall "%~dp0kleinefirewall_windows.py" || goto :fehler
echo.
echo Fertig: dist\KleineFirewall.exe
pause
exit /b
:fehler
echo Das hat nicht geklappt.
pause
