#include <elf-parser.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

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

	if(biggest <= MIN_LENGTH){
		printf("biggest was %d :(\n", biggest);
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

	fd = open(argv[1], O_RDONLY|O_SYNC);
	if(fd<0) {
		printf("Error %d Unable to open %s\n", fd, argv[1]);
		return 0;
	}

	/* ELF header : at start of file */
	read_elf_header(fd, &eh);
	if(!is_ELF(eh)) {
		return 0;
	}
	if(is64Bit(eh)){
		Elf64_Ehdr eh64;	/* elf-header is fixed size */
		Elf64_Shdr* sh_tbl;	/* section-header table is variable size */

		read_elf_header64(fd, &eh64);
		print_elf_header64(eh64);

		/* Section header table :  */
		sh_tbl = malloc(eh64.e_shentsize * eh64.e_shnum);
		if(!sh_tbl) {
			printf("Failed to allocate %d bytes\n",
					(eh64.e_shentsize * eh64.e_shnum));
		}
		read_section_header_table64(fd, eh64, sh_tbl);
		print_section_headers64(fd, eh64, sh_tbl);

		/* Symbol tables :
		 * sh_tbl[i].sh_type
		 * |`- SHT_SYMTAB
		 *  `- SHT_DYNSYM
		 */
		print_symbols64(fd, eh64, sh_tbl);

		/* Save .text section as text.S
		*/
		save_text_section64(fd, eh64, sh_tbl);

		/* Disassemble .text section
		 * Logs asm instructions to stdout
		 * Currently supports ARMv7
		 */
		disassemble64(fd, eh64, sh_tbl);

	} else{
		Elf32_Shdr* sh_tbl;	/* section-header table is variable size */
		print_elf_header(eh);

		/* Section header table :  */
		sh_tbl = malloc(eh.e_shentsize * eh.e_shnum);
		
		if(!sh_tbl) {
			printf("Failed to allocate %d bytes\n",
					(eh.e_shentsize * eh.e_shnum));
		}

		read_section_header_table(fd, eh, sh_tbl);
		print_section_headers(fd, eh, sh_tbl);

		puts("END");

		char *patchName = getPatchedName(argv[1]);
		duplicateFile(argv[1], patchName);
		int patchFD = open(patchName, O_RDWR);
		
		//writeFileHeader(patchFD, &eh);
		//writeSectionTable(patchFD, &eh, sh_tbl);
		makeSectionExecutable(".data", fd, eh, sh_tbl);
		writeSectionTable(patchFD, &eh, sh_tbl);

		int readByts;
		char *codeSection = extractCodeSection(fd, eh, sh_tbl, &readByts);
		printf("%d\n", readByts);
		write(1, codeSection, 10);

		puts("================ CODE CAVE ================");

		int caveSize;
		char *cave = findLongestCave(codeSection, readByts, &caveSize);

		printf("Cave size = %d\n", caveSize);

		// TODO: Make this copy the org file and only change the fields instead of copynig individualy
		exit(0);



		/* Symbol tables :
		 * sh_tbl[i].sh_type
		 * |`- SHT_SYMTAB
		 *  `- SHT_DYNSYM
		 */
		print_symbols(fd, eh, sh_tbl);

		/* Save .text section as text.S
		*/
		save_text_section(fd, eh, sh_tbl);

		/* Disassemble .text section
		 * Logs asm instructions to stdout
		 * Currently supports ARMv7
		 */
		disassemble(fd, eh, sh_tbl);
	}

	return 0;

}

