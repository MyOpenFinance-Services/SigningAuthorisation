@echo off
set "JARFILE="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JARFILE set "JARFILE=..\target\%%F"
)

if not defined JARFILE (
    echo Kein passendes JAR gefunden.
    exit /b 1
)

java -jar "%JARFILE%" sign --alg PS512 --payload Payload.json --key-dir .\ --key-file ps512_key.pem --out-format compact --out .\result\ps512_compact_detached.jws --sigT CURRENT --sub aPaymentResID --cert-dir .\ --cert-file ps512_cert.pem --detached
