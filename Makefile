SOURCES = main.cpp \
          tracker.cpp

OBJECTS := $(addsuffix .o, $(addprefix .build/, $(basename $(SOURCES))))
DEPFILES := $(subst .o,.dep, $(subst .build/,.deps/, $(OBJECTS)))

CPPFLAGS ?= -Wall -O2 -std=c++11
LDLIBS ?= -lstdc++ -lpthread -lpcap -lboost_program_options

DEPCPPFLAGS = -MMD -MP -MF .deps/$(basename $<).dep
PHLEGETHON := $(if $(COMSPEC), phlegethon.exe, phlegethon)

all: phlegethon

.build/%.o: %.cpp
	@mkdir -p .deps/$(dir $<) .build/$(dir $<)
	$(COMPILE.cpp) $(DEPCPPFLAGS) -o $@ $<

phlegethon: $(OBJECTS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

clean:
	@rm -rf .deps/ .build/ $(PHLEGETHON)

-include $(DEPFILES)
