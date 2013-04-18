SOURCES = main.cpp \
          tracker.cpp \
          net.cpp \
          peer_analysis.cpp \
          stats.cpp \
          pcap_manager.cpp \
          config.cpp

BASE_NAME := phlegethon
OUTPUT_NAME := $(if $(COMSPEC), $(BASE_NAME).exe, $(BASE_NAME))

OBJECTS := $(addsuffix .o, $(addprefix .build/, $(basename $(SOURCES))))
DEPFILES := $(subst .o,.dep, $(subst .build/,.deps/, $(OBJECTS)))

CPPFLAGS ?= -Wall -O2 -std=c++11
LDLIBS ?= -lstdc++ -lpthread -lpcap -lboost_program_options

DEPCPPFLAGS = -MMD -MP -MF .deps/$(basename $<).dep

all: $(OUTPUT_NAME)

.build/%.o: %.cpp
	@mkdir -p .deps/$(dir $<) .build/$(dir $<)
	$(COMPILE.cpp) $(DEPCPPFLAGS) -o $@ $<

$(OUTPUT_NAME): $(OBJECTS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

clean:
	@rm -rf .deps/ .build/ $(PHLEGETHON)

-include $(DEPFILES)
