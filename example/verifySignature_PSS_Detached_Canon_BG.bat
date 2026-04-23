@echo off
set "JARFILE="

for /f "delims=" %%F in ('dir /b /a-d /o-n "..\target\SigningAuthorisation-*-all.jar"') do (
    if not defined JARFILE set "JARFILE=..\target\%%F"
)

if not defined JARFILE (
    echo Kein passendes JAR gefunden.
    exit /b 1
)


@echo ##Attention: When SigCmd is using parameter canonicalize-payload, you should use the JSON4Signature... output as input of VerifyCmd
@echo              or set parameter --canonicalize-payload jcs
@echo ## with the parameter --alg ph  the signature alg defined in protected header is used automatically

@echo --> with canonicalize-payload as payload
java -jar "%JARFILE%" verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload .\result\JSON4Signatureps512_bg_detached_canon.jws.json  --detached

@echo --> with original payload as payload
java -jar "%JARFILE%" verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload Payload.json --canonicalize-payload jcs --detached

