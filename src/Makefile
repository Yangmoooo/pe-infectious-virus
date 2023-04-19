# Define the C++ compiler
CXX = g++

# Define the compile flags
CXXFLAGS = -Wall -g

# Define the source file list
SRCS = hello0.cpp hello1.cpp

# Define the object file list
OBJS = $(SRCS:.cpp=.o)

# Define the executable file names
EXES = $(SRCS:.cpp=.exe)

# The first is default
all: $(EXES)
	@echo Compilation completed

$(EXES): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $<

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Define the clean rules
clean:
	del *.o *~ $(EXES)