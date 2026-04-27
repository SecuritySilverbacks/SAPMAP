@echo off
REM SAPMAP - build the SSFS decryption JNI helper jar on Windows.
REM
REM Prereqs: JDK 8+ on PATH (javac, jar).
REM
REM Output: decrypt-ssfs.jar
REM Usage:  java -Dscc.jni.lib=C:\path\to\sapscc20jni.dll -jar decrypt-ssfs.jar

setlocal
if not exist build mkdir build
javac -d build SecStoreAccess.java SecStoreAccessException.java
if errorlevel 1 (
    echo javac failed
    exit /b 1
)
jar cfe decrypt-ssfs.jar com.sap.scc.jni.SecStoreAccess -C build .
if errorlevel 1 (
    echo jar failed
    exit /b 1
)
echo Built decrypt-ssfs.jar - point sapmap_scc_ssfs_decrypt at this file.
endlocal
