DEPS_FILES := \
	Composite-MLKEM-CMS-2026.asn \
	./example/MLKEM768-ECDH-P256-SHA3-256.pub \
	./example/MLKEM768-ECDH-P256-SHA3-256.keyid \
	./example/MLKEM768-ECDH-P256-SHA3-256.cms \
	./example/MLKEM768-ECDH-P256-SHA3-256.cms.txt \
	./example/MLKEM768-ECDH-P256-SHA3-256.priv \
	./example/cek.txt \
	./example/ciphertext.txt \
	./example/decrypted.txt \
	./example/encrypted_cek.txt \
	./example/kek.txt \
	./example/ori_info.txt \
	./example/plaintext.txt \
	./example/shared_secret.txt

LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
