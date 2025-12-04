PKG_NAME := xml_sanitize
VERSION := 1.0.0

SRCDIR := src
INCDIR := include
INCDIRPRIV := include_priv
BUILDDIR := build
LIBDIR := lib
TESTDIR := tests

CC ?= gcc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -pedantic -std=c11
CFLAGS += -I$(INCDIR) -I$(INCDIRPRIV) -I$(SRCDIR)
CFLAGS += -D_POSIX_C_SOURCE=200809L
LDFLAGS :=

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -g -O0 -DDEBUG
    BUILDDIR := $(BUILDDIR)/debug
else
    CFLAGS += -O2 -DNDEBUG
    BUILDDIR := $(BUILDDIR)/release
endif

SANITIZE ?= 0
ifeq ($(SANITIZE), 1)
    CFLAGS += -fsanitize=address,undefined
    LDFLAGS += -fsanitize=address,undefined
endif

USE_LIBXML2 ?= 0
USE_SCEW ?= 0
USE_EXPAT ?= 0
USE_MXML ?= 0
USE_YXML ?= 0
USE_EZXML ?= 0
USE_ROXML ?= 0

CORE_SRCS := $(SRCDIR)/xml_sanitize.c \
             $(SRCDIR)/backend_custom.c

ifeq ($(USE_LIBXML2), 1)
    CFLAGS += -DXML_SAN_HAVE_LIBXML2
    CFLAGS += $(shell pkg-config --cflags libxml-2.0 2>/dev/null)
    LDFLAGS += $(shell pkg-config --libs libxml-2.0 2>/dev/null)
    CORE_SRCS += $(SRCDIR)/backend_libxml2.c
    BACKENDS += libxml2
endif

ifeq ($(USE_SCEW), 1)
    CFLAGS += -DXML_SAN_HAVE_SCEW
    CFLAGS += $(shell pkg-config --cflags scew 2>/dev/null || echo "-I/usr/include/scew")
    LDFLAGS += $(shell pkg-config --libs scew 2>/dev/null || echo "-lscew -lexpat")
    CORE_SRCS += $(SRCDIR)/backend_scew.c
    BACKENDS += scew
endif

ifeq ($(USE_EXPAT), 1)
    CFLAGS += -DXML_SAN_HAVE_EXPAT
    CFLAGS += $(shell pkg-config --cflags expat 2>/dev/null)
    LDFLAGS += $(shell pkg-config --libs expat 2>/dev/null || echo "-lexpat")
    CORE_SRCS += $(SRCDIR)/backend_expat.c
    BACKENDS += expat
endif

ifeq ($(USE_MXML), 1)
    CFLAGS += -DXML_SAN_HAVE_MXML
    CFLAGS += $(shell pkg-config --cflags mxml 2>/dev/null || echo "-I/usr/include")
    LDFLAGS += $(shell pkg-config --libs mxml 2>/dev/null || echo "-lmxml")
    CORE_SRCS += $(SRCDIR)/backend_mxml.c
    BACKENDS += mxml
endif

ifeq ($(USE_YXML), 1)
    CFLAGS += -DXML_SAN_HAVE_YXML
    CFLAGS += $(shell pkg-config --cflags yxml 2>/dev/null || echo "-I/usr/include")
    LDFLAGS += $(shell pkg-config --libs yxml 2>/dev/null || echo "-lyxml")
    CORE_SRCS += $(SRCDIR)/backend_yxml.c
    BACKENDS += yxml
endif

ifeq ($(USE_EZXML), 1)
    CFLAGS += -DXML_SAN_HAVE_EZXML
    CFLAGS += $(shell pkg-config --cflags ezxml 2>/dev/null || echo "-I/usr/include")
    LDFLAGS += $(shell pkg-config --libs ezxml 2>/dev/null || echo "-lezxml")
    CORE_SRCS += $(SRCDIR)/backend_ezxml.c
    BACKENDS += ezxml
endif

ifeq ($(USE_ROXML), 1)
    CFLAGS += -DXML_SAN_HAVE_ROXML
    CFLAGS += $(shell pkg-config --cflags libroxml 2>/dev/null)
    LDFLAGS += $(shell pkg-config --libs libroxml 2>/dev/null || echo "-lroxml")
    CORE_SRCS += $(SRCDIR)/backend_roxml.c
    BACKENDS += roxml
endif

# Always have custom backend
BACKENDS += custom

OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(CORE_SRCS))

STATIC_LIB := $(LIBDIR)/lib$(PKG_NAME).a
SHARED_LIB := $(LIBDIR)/lib$(PKG_NAME).so.$(VERSION)
SHARED_LIB_LINK := $(LIBDIR)/lib$(PKG_NAME).so

TEST_SRCS := $(wildcard $(TESTDIR)/*.c)
TEST_BINS := $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/test_%,$(TEST_SRCS))

.PHONY: all clean install uninstall test

all: static shared

$(BUILDDIR) $(LIBDIR):
	@mkdir -p $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -fPIC -c $< -o $@

static: $(STATIC_LIB)

$(STATIC_LIB): $(OBJS) | $(LIBDIR)
	@echo "  AR    $@"
	@$(AR) rcs $@ $^

shared: $(SHARED_LIB)

$(SHARED_LIB): $(OBJS) | $(LIBDIR)
	@echo "  LD    $@"
	@$(CC) -shared -Wl,-soname,lib$(PKG_NAME).so.1 -o $@ $^ $(LDFLAGS)
	@ln -sf $(notdir $(SHARED_LIB)) $(SHARED_LIB_LINK)
	@ln -sf $(notdir $(SHARED_LIB)) $(LIBDIR)/lib$(PKG_NAME).so.1

test: $(TEST_BINS)
	@echo "Running tests..."
	@for test in $(TEST_BINS); do \
		echo "  TEST  $$(basename $$test)"; \
		LD_LIBRARY_PATH=$(LIBDIR) $$test || exit 1; \
	done
	@echo "All tests passed!"

$(BUILDDIR)/test_%: $(TESTDIR)/%.c $(STATIC_LIB)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) $< -o $@ -L$(LIBDIR) -l$(PKG_NAME) $(LDFLAGS)

PREFIX ?= /usr/local
INSTALL_INCDIR := $(PREFIX)/include
INSTALL_LIBDIR := $(PREFIX)/lib
INSTALL_PKGCONFIG := $(PREFIX)/lib/pkgconfig

install: all
	@echo "Installing to $(PREFIX)..."
	@install -d $(INSTALL_INCDIR)
	@install -d $(INSTALL_LIBDIR)
	@install -d $(INSTALL_PKGCONFIG)
	@install -m 644 $(INCDIR)/*.h $(INSTALL_INCDIR)/
	@install -m 644 $(STATIC_LIB) $(INSTALL_LIBDIR)/
	@install -m 755 $(SHARED_LIB) $(INSTALL_LIBDIR)/
	@ln -sf lib$(PKG_NAME).so.$(VERSION) $(INSTALL_LIBDIR)/lib$(PKG_NAME).so
	@ln -sf lib$(PKG_NAME).so.$(VERSION) $(INSTALL_LIBDIR)/lib$(PKG_NAME).so.1
	@sed -e 's|@PREFIX@|$(PREFIX)|g' \
	     -e 's|@VERSION@|$(VERSION)|g' \
	     xml_sanitize.pc.in > $(INSTALL_PKGCONFIG)/xml_sanitize.pc
	@ldconfig 2>/dev/null || true
	@echo "Installation complete."

uninstall:
	@echo "Uninstalling from $(PREFIX)..."
	@rm -f $(INSTALL_INCDIR)/xml_sanitize.h
	@rm -f $(INSTALL_LIBDIR)/lib$(PKG_NAME).*
	@rm -f $(INSTALL_PKGCONFIG)/xml_sanitize.pc
	@ldconfig 2>/dev/null || true
	@echo "Uninstallation complete."

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILDDIR) $(LIBDIR)
	@rm -f *.o *.a *.so*

DEPFLAGS = -MT $@ -MMD -MP -MF $(BUILDDIR)/$*.d
$(BUILDDIR)/%.o: CFLAGS += $(DEPFLAGS)

-include $(OBJS:.o=.d)