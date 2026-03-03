:: ## TODO: MaxDB SAP_ALL select and that user in USREFUS table --> Do also for all other databases

set LD_LIBRARY_PATH=myway_or_the_gateway_LINUX\rfcsdk\lib
@echo off
::cls
::echo.
::echo This script creates a user in the system specified
::echo FIX TO MAKE IT WORK FOR JAVA AS WELL
::echo ATTENTION: CODVN MIGHT NEED TO BE SET TO OLDER OR NEWER HASH TYPE DEPENDING ON SYSTEM
::echo ATTENTION: FOR ORACLE YOU MIGHT NEED TO CHANGE THE SCHEMA TO SAP-SID- ON OLDER SYTEMS
::echo username is: GO_IN
::echo password is: andinyougo
::echo.
:: set /p host= Gateway hostname:
:: set /p port= Gateway port:
:: set /p cli= Client:
:: set /p sid= SID:
:: set "dbhost=localhost"
:: set /p dbhost= Database hostname:
:: set /p db= DB type:
:: set /p stack= Stack type:
::echo.
::SETLOCAL ENABLEDELAYEDEXPANSION 
:: ##################################################################################################################################################
:: GENERAL PART

:: SET FILES TO DEFAULT
del test.pl
copy system.pl test.pl

:: Set the to be used PORT in the file test.pl
cd /d %~dp0
if exist testCleaned.pl del testCleaned.pl
Set "OldString=YYYY"
Set "NewString=%2"
set file="test.pl"
for %%F in (%file%) do set outFile="%%~nFCleaned%%~xF"

(
  for /f "skip=2 delims=" %%a in ('find /n /v "" %file%') do (
    set "ln=%%a"
    setlocal enableDelayedExpansion
    set "ln=!ln:*]=!"
    if defined ln set "ln=!ln:%OldString%=%NewString%!"
    echo(!ln!
    endlocal
  )
)>%outFile%

:: Initialize temp helperfile
del test.pl
rename testCleaned.pl test.pl

:: Set the to be used HOSTNAME in the file test.pl
cd /d %~dp0
if exist testCleaned.pl del testCleaned.pl
Set "OldString2=XXXXXXXXXX"
Set "NewString2=%1"
set file="test.pl"
for %%F in (%file%) do set outFile="%%~nFCleaned%%~xF"

(
  for /f "skip=2 delims=" %%a in ('find /n /v "" %file%') do (
    set "ln=%%a"
    setlocal enableDelayedExpansion
    set "ln=!ln:*]=!"
    if defined ln set "ln=!ln:%OldString2%=%NewString2%!"
    echo(!ln!
    endlocal
  )
)>%outFile%
del test.pl
rename testCleaned.pl test.pl

:: ###################CHOOSE DB

if /I '%6'=='1' GOTO Mssql
if /I '%6'=='2' GOTO Maxdb
if /I '%6'=='3' GOTO Hanadb
if /I '%6'=='4' GOTO Oracle
if /I '%6'=='5' GOTO DB2
echo Wrong DB type chosen
exit /B

:: ##################################################################################################################################################
:: MSSQL PART
:Mssql

:: ###################CHOOSE STACK
if %7 == 1 (
    goto Abap
	)
if %7 == 2 (
    goto Java
	)
echo Wrong stack type chosen
exit /B

:: #######BEGIN OF ABAP PART ##########
:Abap

:: Translate SID to uppercase FOR SQL
set sid2=%4
    IF [%sid2%]==[] GOTO:EOF
    SET sid2=%sid2:a=A%
    SET sid2=%sid2:b=B%
    SET sid2=%sid2:c=C%
    SET sid2=%sid2:d=D%
    SET sid2=%sid2:e=E%
    SET sid2=%sid2:f=F%
    SET sid2=%sid2:g=G%
    SET sid2=%sid2:h=H%
    SET sid2=%sid2:i=I%
    SET sid2=%sid2:j=J%
    SET sid2=%sid2:k=K%
    SET sid2=%sid2:l=L%
    SET sid2=%sid2:m=M%
    SET sid2=%sid2:n=N%
    SET sid2=%sid2:o=O%
    SET sid2=%sid2:p=P%
    SET sid2=%sid2:q=Q%
    SET sid2=%sid2:r=R%
    SET sid2=%sid2:s=S%
    SET sid2=%sid2:t=T%
    SET sid2=%sid2:u=U%
    SET sid2=%sid2:v=V%
    SET sid2=%sid2:w=W%
    SET sid2=%sid2:x=X%
    SET sid2=%sid2:y=Y%
    SET sid2=%sid2:z=Z%

:: ADD THE "CREATE A USER" PART TO THE REMOTE SQL SCRIPT (This script is placed by default in the WORKdir)
myway_or_the_gateway_LINUX\bin\perl test.pl "echo use %sid2% > a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USR02 (MANDT,BNAME,USTYP,CODVN) VALUES ('%3','GO_IN','S','G') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"

:: ADD THE "UPDATE THE BCODE\PASSCODE" PART TO THE REMOTE SQL SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE %4.USR02 set BCODE=0xC76AB3A59599FE3A where MANDT=%3 and BNAME='GO_IN' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE %4.USR02 set PASSCODE=0xCF017A9A4F1F53ED69CEDC773072B1B24A063A63 where MANDT=%3 and BNAME='GO_IN' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"

:: ADD THE "GIVE IT REFUSER DDIC (Which means SAP_ALL)" PART TO THE REMOTE SQL SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USREFUS (MANDT,BNAME,REFUSER) VALUES ('%3','GO_IN','DDIC') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"

:: ADDITIONALLY ADD SAP_ALL TO USERBUFFER
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.UST04 (MANDT,BNAME,PROFILE) VALUES ('%3','GO_IN','SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USR04 (MANDT,BNAME,NRPRO,PROFS) VALUES ('%3','GO_IN','14','C SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_ADMI_FCD','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_DATASET','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_DEVELOP','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_RFC','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_TABU_DIS','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_TCODE','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_USER_AUT','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_USER_GRP','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_USER_PRO','^&_SAP_ALL') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"



:: EXECUTE THE SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcmd -S %5 -i a.sql"

goto End
:: #######END OF ABAP PART ##########

:: #######BEGIN OF JAVA PART ##########
:Java

:: Translate SID to uppercase FOR SQL
set sid2=%4
    IF [%sid2%]==[] GOTO:EOF
    SET sid2=%sid2:a=A%
    SET sid2=%sid2:b=B%
    SET sid2=%sid2:c=C%
    SET sid2=%sid2:d=D%
    SET sid2=%sid2:e=E%
    SET sid2=%sid2:f=F%
    SET sid2=%sid2:g=G%
    SET sid2=%sid2:h=H%
    SET sid2=%sid2:i=I%
    SET sid2=%sid2:j=J%
    SET sid2=%sid2:k=K%
    SET sid2=%sid2:l=L%
    SET sid2=%sid2:m=M%
    SET sid2=%sid2:n=N%
    SET sid2=%sid2:o=O%
    SET sid2=%sid2:p=P%
    SET sid2=%sid2:q=Q%
    SET sid2=%sid2:r=R%
    SET sid2=%sid2:s=S%
    SET sid2=%sid2:t=T%
    SET sid2=%sid2:u=U%
    SET sid2=%sid2:v=V%
    SET sid2=%sid2:w=W%
    SET sid2=%sid2:x=X%
    SET sid2=%sid2:y=Y%
    SET sid2=%sid2:z=Z%

:: ADD THE "CREATE A USER" PART TO THE REMOTE SQL SCRIPT (This script is placed by default in the WORKdir)
myway_or_the_gateway_LINUX\bin\perl test.pl "echo use %sid2% > a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.UME_STRINGS (MANDT,BNAME,USTYP,CODVN) VALUES ('%3','GO_IN','S','G') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"

:: ADD THE "UPDATE THE BCODE\PASSCODE" PART TO THE REMOTE SQL SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE %4.UME_STRINGS set BCODE=0xC76AB3A59599FE3A where MANDT=%3 and BNAME='GO_IN' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE %4.UME_STRINGS set PASSCODE=0xCF017A9A4F1F53ED69CEDC773072B1B24A063A63 where MANDT=%3 and BNAME='GO_IN' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"

:: ADD THE "GIVE IT REFUSER DDIC (Which means SAP_ALL)" PART TO THE REMOTE SQL SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO %4.USREFUS (MANDT,BNAME,REFUSER) VALUES ('%3','GO_IN','DDIC') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo go >> a.sql"

:: EXECUTE THE SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcmd -S %5 -i a.sql"

goto End
:: #######END OF JAVA PART ##########

:: ##################################################################################################################################################
:: MAXDB PART
:Maxdb

myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USR02 (MANDT,BNAME,BCODE,USTYP,CODVN) VALUES ('%3','GO_IN','C76AB3A59599FE3A','S','G')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT UPDATE USR02 set PASSCODE='CF017A9A4F1F53ED69CEDC773072B1B24A063A63' where BNAME='GO_IN' and mandt='%3'"

:: #Read here all users that have SAP_ALL from ST04 and use the first one of the list as a reference user in the next step
::myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -a -A -Q -U DEFAULT SELECT BNAME from UST04 where PROFILE='SAP_ALL' and mandt='%3'" > SAPALLUSERS.txt
::set /p rootuser= <SAPALLUSERS.txt
::del SAPALLUSERS.txt

:: # Assign the SAP_ALL reference user to GO_IN user
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USREFUS (MANDT,BNAME,REFUSER) VALUES ('%3','GO_IN','DDIC')"

:: ADDITIONALLY ADD SAP_ALL TO USERBUFFER
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO UST04 (MANDT,BNAME,PROFILE) VALUES ('%3','GO_IN','SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USR04 (MANDT,BNAME,NRPRO,PROFS) VALUES ('%3','GO_IN','14','C SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_ADMI_FCD','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_DATASET','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_DEVELOP','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_RFC','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_TABU_DIS','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_TCODE','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_USER_AUT','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_USER_GRP','^&_SAP_ALL')"
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlcli -U DEFAULT INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('%3','GO_IN','S_USER_PRO','^&_SAP_ALL')"


goto End

:: ##################################################################################################################################################
:: HANA DB PART
:Hanadb

:: ADD THE "CREATE A USER" PART TO THE REMOTE SQL SCRIPT (This script is placed by default in the WORKdir)
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO USR02 (MANDT,BNAME,USTYP,CODVN) VALUES ('%3','GO_IN','S','G') > a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo ; >> a.sql"

:: ADD THE "UPDATE THE BCODE\PASSCODE" PART TO THE REMOTE SQL SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE USR02 set BCODE='C76AB3A59599FE3A' where MANDT='%3' and BNAME='GO_IN' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo ; >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE USR02 set PASSCODE='CF017A9A4F1F53ED69CEDC773072B1B24A063A63' where MANDT='%3' and BNAME='GO_IN' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo ; >> a.sql"

:: ADD THE "GIVE IT REFUSER DDIC (Which means SAP_ALL)" PART TO THE REMOTE SQL SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO USREFUS (MANDT,BNAME,REFUSER) VALUES ('%3','GO_IN','DDIC') >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo ; >> a.sql"

:: EXECUTE THE SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "hdbsql -n %5 -i 00 -U DEFAULT -o output.txt -I a.sql"


goto End
:: ##################################################################################################################################################
:: DB2 DB PART
:DB2

myway_or_the_gateway_LINUX\bin\perl test.pl "db2 INSERT INTO USR02 (MANDT,BNAME,BCODE,USTYP,CODVN) VALUES ('%3','GO_IN','C76AB3A59599FE3A','S','G')"
myway_or_the_gateway_LINUX\bin\perl test.pl "db2 UPDATE USR02 set PASSCODE='CF017A9A4F1F53ED69CEDC773072B1B24A063A63' where BNAME='GO_IN' and mandt='%3'"
myway_or_the_gateway_LINUX\bin\perl test.pl "db2 INSERT INTO USREFUS (MANDT,BNAME,REFUSER) VALUES ('%3','GO_IN','DDIC')"


goto End
:: ##################################################################################################################################################
:: ORACLE PART
:Oracle

:: CREATE THE SQL SCRIPT

myway_or_the_gateway_LINUX\bin\perl test.pl "echo connect / as sysdba; > a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO SAPSR3.USR02 (MANDT,BNAME,BCODE,USTYP,CODVN) >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo VALUES ('%3','GO_IN','C76AB3A59599FE3A','S','G'); >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo UPDATE SAPSR3.USR02 set PASSCODE='CF017A9A4F1F53ED69CEDC773072B1B24A063A63' >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo where BNAME='GO_IN' and mandt='%3'; >> a.sql"
myway_or_the_gateway_LINUX\bin\perl test.pl "echo INSERT INTO SAPSR3.USREFUS (MANDT,BNAME,REFUSER) VALUES ('%3','GO_IN','DDIC'); >> a.sql"

:: EXECUTE THE SCRIPT
myway_or_the_gateway_LINUX\bin\perl test.pl "sqlplus -S /NOLOG @a.sql"

goto End

:: ##################################################################################################################################################:: Final PART
:End
:: DELETE TEMP FILES
::del test.pl

::echo FOR ABAP: You can now login with username "GO_IN" and password "andinyougo" in the specified client and system
::echo FOR JAVA: You can now login with username "GO_IN" and password "Andinyoug0" (mind the zero) in the specified system