# SAPMAP — build the SSFS decryption JNI helper jar.
#
# One-time build:  make
# Output:          decrypt-ssfs.jar
# Usage:           java -Dscc.jni.lib=<libsapscc20jni.so> -jar decrypt-ssfs.jar
#
# The jar links against SAP's libsapscc20jni.so / sapscc20jni.dll at
# RUNTIME — no SAP code is compiled or redistributed in this artifact.

JAVAC ?= javac
JAR   ?= jar
SRC    = SecStoreAccess.java SecStoreAccessException.java
JAR_NAME = decrypt-ssfs.jar

all: $(JAR_NAME)

$(JAR_NAME): $(SRC)
	@mkdir -p build
	$(JAVAC) -d build $(SRC)
	$(JAR) cfe $(JAR_NAME) com.sap.scc.jni.SecStoreAccess -C build .
	@echo "Built $(JAR_NAME) — point sapmap_scc_ssfs_decrypt at this file."

clean:
	rm -rf build $(JAR_NAME)

.PHONY: all clean
