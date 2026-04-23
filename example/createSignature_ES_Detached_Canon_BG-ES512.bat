@echo off
set "JARFILE="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JARFILE set "JARFILE=..\target\%%F"
)

if not defined JARFILE (
    echo Kein passendes JAR gefunden.
    exit /b 1
)

java -jar "%JARFILE%" sign --alg ES512 --payload Payload.json --key-dir .\ --key-file es512_key_pkcs8.pem --out-format bg --out .\result\ES512_bg_detached_canon.jws --iat --x5t#S256 --sub aPaymentResID --cert-dir .\ --cert-file es512_cert.pem --canonicalize-payload jcs --critClaimList b64,sigT,sigD --detached
