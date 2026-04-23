@echo off
setlocal


set "JAR="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JAR set "JAR=..\target\%%F"
)

if not defined JAR (
    echo Kein passendes JAR gefunden.
    exit /b 1
)


java -jar "%JAR%" verify-xml ^
  --format xades ^
  --in ".\result\pain001-signature.xml" ^
  --payload ".\pain001.xml" ^
  --truststore ".\DSS_TrustStore.p12" ^
  --truststoreType "PKCS12" ^
  --truststorePassword "password" ^
  --debug

if errorlevel 1 (
  echo.
  echo XAdES verification failed.
  exit /b 1
)

echo.
echo XAdES verification finished successfully.

endlocal