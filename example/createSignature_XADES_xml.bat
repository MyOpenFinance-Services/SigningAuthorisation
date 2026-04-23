@echo off
setlocal

@echo off
set "JAR="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JAR set "JAR=..\target\%%F"
)

if not defined JAR (
    echo Kein passendes JAR gefunden.
    exit /b 1
)


set PAYLOAD=.\pain001.xml
set OUT=.\result\pain001-signature.xml

set KEYSTORE=.\DSS_TrustKeyStore.p12
set KEYSTORE_TYPE=PKCS12
set KEYSTORE_PASSWORD=password
set KEY_ALIAS=ps512
set KEY_PASSWORD=password
set RES_ID=pain001.myResourceId1234


java -jar "%JAR%" sign-xml ^
  --format xades ^
  --alg RS512 ^
  --payload "%PAYLOAD%" ^
  --out "%OUT%" ^
  --keystore "%KEYSTORE%" ^
  --keystoreType "%KEYSTORE_TYPE%" ^
  --keystorePassword "%KEYSTORE_PASSWORD%" ^
  --keyAlias "%KEY_ALIAS%" ^
  --keyPassword "%KEY_PASSWORD%" ^
  --referenceURI "%RES_ID%" ^
  --debug

if errorlevel 1 (
  echo.
  echo XAdES signing failed.
  exit /b 1
)

echo.
echo XAdES signing finished successfully.
echo Signature file: %OUT%

endlocal