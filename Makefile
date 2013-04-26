SOURCES = main.cpp \
          tracker.cpp \
          net.cpp \
          peer_analysis.cpp \
          stats.cpp \
          pcap_manager.cpp \
          config.cpp

BASE_NAME := phlegethon

ifdef COMSPEC
  OUTPUT_NAME ?= $(BASE_NAME).exe
  BOOST_LIBS ?= thread program_options system chrono exception
  BOOST_FLAGS ?= -DBOOST_THREAD_USE_LIB
  LDLIBS ?= $(addprefix -lboost_, $(BOOST_LIBS)) -lwpcap -lws2_32 -lstdc++ -static
else
  OUTPUT_NAME ?= $(BASE_NAME)
  BOOST_LIBS ?= program_options
  LDLIBS ?= $(addprefix -lboost_, $(BOOST_LIBS)) -lpcap -lpthread -lstdc++
endif

DEPFLAGS ?= -MMD -MP -MF .deps/$(basename $<).dep
CPPFLAGS ?= -Wall -O2 -std=c++11 $(BOOST_FLAGS)

OBJECTS := $(addsuffix .o, $(addprefix .build/, $(basename $(SOURCES))))
DEPFILES := $(subst .o,.dep, $(subst .build/,.deps/, $(OBJECTS)))

all: $(OUTPUT_NAME)

.build/%.o: %.cpp
	@mkdir -p .deps/$(dir $<) .build/$(dir $<)
	$(COMPILE.cpp) $(DEPFLAGS) -o $@ $<

$(OUTPUT_NAME): $(OBJECTS)
	$(LINK.o) $^ $(LDLIBS) -o $@

clean:
	@rm -rf .deps/ .build/ $(PHLEGETHON)

-include $(DEPFILES)
