# Might not be the prettiest Makefile but it does the job
PRIVATE_KEY=data/encryptKey.key
PUBLIC_KEY_CERTIFICATE=data/encryptCert.crt
SIGN_CERTIFICATE=data/signCert.crt
SIGN_KEY=data/signKey.key
TEST_FILE=data/testdoc.txt
TEST_FILE_ENCRYPTED=./testdoc_enc.txt
TEST_FILE_UNCRYPTED=./testdoc_dec.txt
SUBMISSION_PLAINTEXT=data/submission.txt
SUBMISSION_PLAINTEXT_ENCRYPTED=./submission_enc.txt
SUBMISSION_PLAINTEXT_DECRYPTED=./submission_dec.txt
MAC_PASSWORD=supersecret
SL_DECRYPT=ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt
SL_ENCRYPT=ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt
BOUNCYCASTLE_JAR=~/bcprov-jdk18on-177.jar

build:
	mvn package

clean:
	rm -r target/

build_submission_file: build
	@echo "Encrypting with: AES/CBC/PKCS5Padding"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(SUBMISSION_PLAINTEXT) \
		$(SUBMISSION_PLAINTEXT_ENCRYPTED).1 \
		$(PUBLIC_KEY_CERTIFICATE) \
		AES/CBC/PKCS5Padding \
		192 \
		N
	@echo
	@echo "Encrypting with: AES/GCM/NoPadding with auth/int MAC (HmacSHA512)"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(SUBMISSION_PLAINTEXT) \
		$(SUBMISSION_PLAINTEXT_ENCRYPTED).2 \
		$(PUBLIC_KEY_CERTIFICATE) \
		AES/GCM/NoPadding \
		256 \
		M \
		HmacSHA512 \
		$(MAC_PASSWORD)
	@echo
	@echo "Encrypting with: SEED/CTR/NoPadding with auth/int MAC (HmacSHA3-512)"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(SUBMISSION_PLAINTEXT) \
		$(SUBMISSION_PLAINTEXT_ENCRYPTED).3 \
		$(PUBLIC_KEY_CERTIFICATE) \
		SEED/CTR/NoPadding \
		128 \
		M \
		HmacSHA3-512 \
		$(MAC_PASSWORD)
	@echo
	@echo "Encrypting with: RC4 with auth/int Signature (SHA512withRSA)"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(SUBMISSION_PLAINTEXT) \
		$(SUBMISSION_PLAINTEXT_ENCRYPTED).4 \
		$(PUBLIC_KEY_CERTIFICATE) \
		RC4 \
		128 \
		S \
		SHA512withRSA \
		$(SIGN_KEY) \
		$(SIGN_CERTIFICATE)
	@echo
	@echo "Encrypting with: CHACHA20 with auth/int Signature (SHA3-512withRSA)"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(SUBMISSION_PLAINTEXT) \
		$(SUBMISSION_PLAINTEXT_ENCRYPTED).5 \
		$(PUBLIC_KEY_CERTIFICATE) \
		CHACHA20 \
		256 \
		S \
		SHA3-512withRSA \
		$(SIGN_KEY) \
		$(SIGN_CERTIFICATE)

test_all: test_aes_cbc_pkcs5 test_aes_gcm test_seed_ctr test_rc4 test_chacha20

test_aes_cbc_pkcs5: build
	@echo "Encrypting with: AES/CBC/PKCS5Padding and auth/int via MAC"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(TEST_FILE) \
		$(TEST_FILE_ENCRYPTED) \
		$(PUBLIC_KEY_CERTIFICATE) \
		AES/CBC/PKCS5Padding \
		192 \
		M \
		HmacSHA512 \
		$(MAC_PASSWORD)
	@echo
	@echo
	@echo "Decrypting with: AES/CBC/PKCS5Padding"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_DECRYPT) \
		$(TEST_FILE_ENCRYPTED) \
		$(TEST_FILE_UNCRYPTED) \
		$(PRIVATE_KEY) \
		$(MAC_PASSWORD)
	@cd target/classes; diff $(TEST_FILE) $(TEST_FILE_UNCRYPTED) > /dev/null || \
		echo "AES/CBC/PKCS5Padding ENCRYPTION / DECRYPTION FAILED"
	@echo
	@echo

test_aes_gcm: build
	@echo "Encrypting with: AES/GCM/NoPadding and auth/int via MAC"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(TEST_FILE) \
		$(TEST_FILE_ENCRYPTED) \
		$(PUBLIC_KEY_CERTIFICATE) \
		AES/GCM/NoPadding \
		256 \
		M \
		HmacSHA3-512 \
		$(MAC_PASSWORD)
	@echo
	@echo
	@echo "Decrypting with: AES/GCM/NoPadding"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_DECRYPT) \
		$(TEST_FILE_ENCRYPTED) \
		$(TEST_FILE_UNCRYPTED) \
		$(PRIVATE_KEY) \
		$(MAC_PASSWORD)
	@cd target/classes; diff $(TEST_FILE) $(TEST_FILE_UNCRYPTED) > /dev/null || \
		echo "AES/GCM/NoPadding ENCRYPTION / DECRYPTION FAILED"
	@echo
	@echo

test_seed_ctr: build
	@echo "Encrypting with: SEED/CTR/NoPadding"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(TEST_FILE) \
		$(TEST_FILE_ENCRYPTED) \
		$(PUBLIC_KEY_CERTIFICATE) \
		SEED/CTR/NoPadding \
		128 \
		S \
		SHA512withRSA \
		$(SIGN_KEY) \
		$(SIGN_CERTIFICATE)
	@echo
	@echo
	@echo "Decrypting with: SEED/CTR/NoPadding"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_DECRYPT) \
		$(TEST_FILE_ENCRYPTED) \
		$(TEST_FILE_UNCRYPTED) \
		$(PRIVATE_KEY)
	@cd target/classes; diff $(TEST_FILE) $(TEST_FILE_UNCRYPTED) > /dev/null || \
		echo "SEED/CTR/NoPadding ENCRYPTION / DECRYPTION FAILED"
	@echo
	@echo

test_rc4: build
	@echo "Encrypting with: RC4"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(TEST_FILE) \
		$(TEST_FILE_ENCRYPTED) \
		$(PUBLIC_KEY_CERTIFICATE) \
		RC4 \
		128 \
		S \
		SHA3-512withRSA \
		$(SIGN_KEY) \
		$(SIGN_CERTIFICATE)
	@echo
	@echo
	@echo "Decrypting with: RC4"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_DECRYPT) \
		$(TEST_FILE_ENCRYPTED) \
		$(TEST_FILE_UNCRYPTED) \
		$(PRIVATE_KEY)
	@cd target/classes; diff $(TEST_FILE) $(TEST_FILE_UNCRYPTED) > /dev/null || \
		echo "RC4 ENCRYPTION / DECRYPTION FAILED"
	@echo
	@echo

test_chacha20: build
	@echo "Encrypting with: CHACHA20 and no auth/int protection"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_ENCRYPT) \
		$(TEST_FILE) \
		$(TEST_FILE_ENCRYPTED) \
		$(PUBLIC_KEY_CERTIFICATE) \
		CHACHA20 \
		256 \
		N
	@echo
	@echo
	@echo "Decrypting with: CHACHA20"
	@echo
	@cd target/classes; java -cp $(BOUNCYCASTLE_JAR):. \
		$(SL_DECRYPT) \
		$(TEST_FILE_ENCRYPTED) \
		$(TEST_FILE_UNCRYPTED) \
		$(PRIVATE_KEY)
	@cd target/classes; diff $(TEST_FILE) $(TEST_FILE_UNCRYPTED) > /dev/null || \
		echo "CHACHA20 ENCRYPTION / DECRYPTION FAILED"
	@echo
	@echo

