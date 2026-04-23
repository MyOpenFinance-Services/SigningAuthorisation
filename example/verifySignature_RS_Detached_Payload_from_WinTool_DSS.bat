@echo on
REM --truststore <file>
REM --truststoreType <PKCS12|jks>
REM --truststorePassword <password>
REM --validationPolicy <xml-file>

@echo off
set "JARFILE="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JARFILE set "JARFILE=..\target\%%F"
)

if not defined JARFILE (
    echo Kein passendes JAR gefunden.
    exit /b 1
)


echo ===IMPORTANT==== "Payload.json" needs to be stored under ".\result" and signature created by DSS Tool and needs to be stored under ".\result\Payload-Signature.json"

echo =================- JSON payload crypto
java -jar "%JARFILE%" verify --mode crypto --alg ph --in .\result\Payload-Signature.json --pub-dir .\ --pub-file ps512_cert.pem --payload .\result\Payload.json  --truststorePassword password --detached --debug


echo =================- JSON payload eidas
java -jar "%JARFILE%" verify --mode eidas --alg ph --in .\result\Payload-Signature.json --payload .\result\Payload.json --truststore DSS_TrustKeyStore.p12 --truststoreType PKCS12 --truststorePassword password --validationPolicy .\default-constraint-WebAPP.xml --detached --debug

