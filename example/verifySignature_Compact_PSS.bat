@echo off
set "JARFILE="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JARFILE set "JARFILE=..\target\%%F"
)

if not defined JARFILE (
    echo Kein passendes JAR gefunden.
    exit /b 1
)

java -jar "%JARFILE%" verify --mode crypto --alg PS512 --in .\result\ps512_compact.jws --pub-dir .\ --pub-file ps512_cert.pem