@echo off
set "JARFILE="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JARFILE set "JARFILE=..\target\%%F"
)

if not defined JARFILE (
    echo Kein passendes JAR gefunden.
    exit /b 1
)

java -jar "%JARFILE%" sign --alg RS512 --payload pain001.xml --key-dir .\ --key-file ps512_key.pem --out-format json --out .\result\RS512_jose_detached_XML.jws --iat --x5t#S256 --sub aPaymentResID --cert-dir .\ --cert-file ps512_cert.pem --critClaimList b64,sigD --detached
