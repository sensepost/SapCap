#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=
AS=as

# Macros
CND_PLATFORM=GNU-MacOSX
CND_CONF=Release
CND_DISTDIR=dist

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=build/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/vpa105CsObjInt.o \
	${OBJECTDIR}/vpa106cslzc.o \
	${OBJECTDIR}/SapLib.o \
	${OBJECTDIR}/vpa107cslzh.o \
	${OBJECTDIR}/vpa108csulzh.o

# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	${MAKE}  -f nbproject/Makefile-Release.mk dist/Release/GNU-MacOSX/libSapCompress.dylib

dist/Release/GNU-MacOSX/libSapCompress.dylib: ${OBJECTFILES}
	${MKDIR} -p dist/Release/GNU-MacOSX
	${LINK.cc} -dynamiclib -install_name libSapCompress.dylib -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/libSapCompress.dylib -fPIC ${OBJECTFILES} ${LDLIBSOPTIONS} 

${OBJECTDIR}/vpa105CsObjInt.o: nbproject/Makefile-${CND_CONF}.mk vpa105CsObjInt.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF $@.d -o ${OBJECTDIR}/vpa105CsObjInt.o vpa105CsObjInt.cpp

${OBJECTDIR}/vpa106cslzc.o: nbproject/Makefile-${CND_CONF}.mk vpa106cslzc.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF $@.d -o ${OBJECTDIR}/vpa106cslzc.o vpa106cslzc.cpp

${OBJECTDIR}/SapLib.o: nbproject/Makefile-${CND_CONF}.mk SapLib.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF $@.d -o ${OBJECTDIR}/SapLib.o SapLib.cpp

${OBJECTDIR}/vpa107cslzh.o: nbproject/Makefile-${CND_CONF}.mk vpa107cslzh.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF $@.d -o ${OBJECTDIR}/vpa107cslzh.o vpa107cslzh.cpp

${OBJECTDIR}/vpa108csulzh.o: nbproject/Makefile-${CND_CONF}.mk vpa108csulzh.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF $@.d -o ${OBJECTDIR}/vpa108csulzh.o vpa108csulzh.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r build/Release
	${RM} dist/Release/GNU-MacOSX/libSapCompress.dylib

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
