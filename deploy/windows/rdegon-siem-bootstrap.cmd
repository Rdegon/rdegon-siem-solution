@echo off
setlocal

set "SCRIPT=%USERPROFILE%\Documents\RdegonSIEM\rdegon-siem-collector.ps1"
set "STATE=%LOCALAPPDATA%\RdegonSIEM\collector-state.json"
set "TASK=RdegonSIEMCollector"
set "BASEURL=https://192.168.1.35"
set "ROUTINGMODE=ports"
set "SHAREDSECRET=%~1"

if not exist "%USERPROFILE%\Documents\RdegonSIEM" (
    mkdir "%USERPROFILE%\Documents\RdegonSIEM" >nul 2>&1
)

schtasks /Query /TN "%TASK%" >nul 2>&1
if errorlevel 1 (
    if not "%SHAREDSECRET%"=="" (
        schtasks /Create /SC MINUTE /MO 5 /TN "%TASK%" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\" -BaseUrl \"%BASEURL%\" -StatePath \"%STATE%\" -RoutingMode %ROUTINGMODE% -SharedSecret \"%SHAREDSECRET%\"" /F >nul 2>&1
    ) else (
        schtasks /Create /SC MINUTE /MO 5 /TN "%TASK%" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\" -BaseUrl \"%BASEURL%\" -StatePath \"%STATE%\" -RoutingMode %ROUTINGMODE%" /F >nul 2>&1
    )
)

if not "%SHAREDSECRET%"=="" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -BaseUrl "%BASEURL%" -StatePath "%STATE%" -RoutingMode %ROUTINGMODE% -SharedSecret "%SHAREDSECRET%"
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -BaseUrl "%BASEURL%" -StatePath "%STATE%" -RoutingMode %ROUTINGMODE%
)
endlocal
