#ifdef _WIN32
#include <windows.h>
#else
#define MAX_PATH	255
#define BOOL		uint32_t
#define TRUE		0x01
#define FALSE		0x00
#endif

#include "crypt.h"
#include "util.h"
#include "tables.h"


#define DEFAULT_FILENAME	"lv0.elf"
#define DEFAULT_FILEPATH	".\\"


#define ELF_HEADER_SIG		0x7f454c46
#define SELF_HEADER_SIG		0x53434500
#define NUM_EMBEDDED_LDRS	0x04


////////////////////////////
// declare globals here

char* g_pszLdrNames[NUM_EMBEDDED_LDRS] = {
		"lv1ldr.self",
		"lv2ldr.self",
		"isoldr.self",
		"appldr.self"
	};
//
//////////////////////////



// function declarations
void extract_ldrs(uint8_t *in, uint32_t size, char* szFilePath);
void usage (char* pszInParam);
int select_string(char* pszInString);




void crypt_lv1ldr(uint8_t *in, uint32_t size, uint8_t *erk, uint8_t *riv)
{
	sfc_context_t *ctx;
	uint32_t rounded_size;

	rounded_size = round_up(size, SFC_BLOCK_SIZE);

	ctx = sfc_create_context(erk, riv);
	if (ctx) {
		//sfc_process_data(ctx, in, out, rounded_size);
		sfc_process_data(ctx, in, in, rounded_size);
		sfc_destroy_context(ctx);
	}
	else {
		printf("ctx fail\n");
	}

	//return out;
}

//////////////////////////////////////////////////////////////////////////////
//
void extract_ldrs(uint8_t *in, uint32_t size, char* szFilePath)
{
	uint32_t ldr_size, i = 0;
	char szOutFileName[MAX_PATH] = {0};
	int ldr = 0;

	for(i=0;i<size;i+=4)
	{
		// find the next "SELF" header
		if(be32(in+i) == SELF_HEADER_SIG)
		{
			if(ldr >= NUM_EMBEDDED_LDRS)
				break;

			ldr_size = (uint32_t)(be64(in+i+0x10) + be64(in+i+0x18));
			printf("extracting ldr:%s at %x size: %x bytes\n", g_pszLdrNames[ldr], i, ldr_size);
			
			sprintf_s(szOutFileName, MAX_PATH, "%s\\%s", szFilePath, g_pszLdrNames[ldr]);
			write_file(szOutFileName, in+i, ldr_size);
			ldr++;
		}
	}
}
//
///////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////
//
void import_ldrs(uint8_t *in, uint32_t size, char* szInPath)
{
	uint32_t ldr_size, import_size, i = 0;
	uint8_t *ldr = NULL;
	char szInFileName[MAX_PATH] = {0};	
	int found = 0;

	for(i=0;i<size;i+=4)
	{
		if(be32(in+i) == SELF_HEADER_SIG)
		{
			if(found >= NUM_EMBEDDED_LDRS)
				break;

			//sprintf_s(name, MAX_PATH, "ldr_%i", j);
			sprintf_s(szInFileName, MAX_PATH, "%s\\%s", szInPath, g_pszLdrNames[found]);

			ldr_size = (uint32_t)(be64(in+i+0x10) + be64(in+i+0x18));
			if (read_entire_file(szInFileName, (void **)&ldr, &import_size, SFC_BLOCK_SIZE) < 0) {
				printf("\nERROR: read_file failed:%s", szInFileName);
				exit(1);
			}
			if( (ldr_size == import_size) && (be64(in+i+0x70) == be64(ldr+0x70)) )
			{
				printf("importing ldr:%s at 0x%x size: 0x%x bytes\n", g_pszLdrNames[found], i, ldr_size);
				memcpy(in+i, ldr, ldr_size);
			} 
			else if( (import_size < ldr_size) && (be64(in+i+0x70) == be64(ldr+0x70)) )
			{
				printf("importing smaller ldr:%s at 0x%x, size:0x%x (expected:0x%x) bytes\n", g_pszLdrNames[found], i, import_size, ldr_size);
				// fill the ldr location with 0s, since our "new size" is smaller
				// than the original size...then copy over new image
				memset(in+i, 0, ldr_size);
				memcpy(in+i, ldr, import_size);
			}
			else {
				printf("import failed: file does not match: %s\n\tsize:0x%x expected:0x%x\n\t auth id: 0x%llx expected: 0x%llx\n", g_pszLdrNames[found], import_size, ldr_size, be64(ldr+0x70), be64(in+i+0x70));
				exit(1);
			}
			found++;

		} // if (SCE...)
	} // for (i = 0...)
}
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////



uint8_t * get_lv1ldr(uint8_t * in, uint32_t size)
{
	uint32_t lv1ldr_ptr = binsearch64(in, size, 0x1800000000ULL) + 0xC;
	return in + lv1ldr_ptr;
}

uint32_t get_lv1ldr_size(uint8_t * in, uint32_t size, uint32_t addr)
{
	uint32_t va = ra_to_va(in, addr);
	//printf("va %x\n", va);
	uint32_t ptr_lv1ldr = reverse_binsearch64(in, size, va);
	//printf("lv1ldr_ptr %x->\n", ptr_lv1ldr, ra_to_va(in, ptr_lv1ldr));
	return (uint32_t) be64(in + ptr_lv1ldr + 8);
}

////////////////////////////////////////////////////////////////
//// usage function ///////
void usage (char* pszInParam)
{
	if (pszInParam != NULL)
		printf("\nParameter: \"%s\" is invalid!\n", pszInParam);

	printf("Usage:  LV0TOOL:  -option  -filename  -filepath  -lv1crypt  -cleanup\n\n");
	printf("Arguments:\n");
	printf("---------\n");
	printf("-option:\n");
	printf("\tIMPORT:	import loaders into LV0\n");
	printf("\tEXPORT:	extract loaders from LV0\n\n");
	printf("-filename:\t** optional **\n\tname of LV0 file\n");
	printf("\t(default: lv0.elf\n\n");
	printf("-filepath:\t** optional **\n\tdir path to LV0 file\n");
	printf("\t(default: .\\)\n\n");
	printf("-lv1crypt:\t** optional **\n");
	printf("\tYES:	do crypt of lv1ldr before import/export ** default **\n");
	printf("\tNO:	do NOT crypt lv1ldr before import/export\n\n");			
	printf("-cleanup:\t** optional **\n");
	printf("\tYES:	delete loaders after import\n");
	printf("\tNO:	do NOT delete loaders after import ** default **\n");

	exit(-1);
}
//
///////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////
/// select_string function ///////
int select_string(char* pszInString)
{
	int i = 0;
	int ret = -1;
	char* params_list[] = {
		"-option",
		"-filename",
		"-filepath",
		"-lv1crypt",
		"-cleanup"
	};

	// for loop to iterate through params list
	for (i = 0; i < (sizeof(params_list)/sizeof*params_list); i++)
	{
		if ( strcmp(pszInString, params_list[i]) == 0 ) {
			ret = i;
			break;
		}
	}

	return ret;
}
//
/////////////////////////////////////////////////////////



int __cdecl main(int argc, char *argv[])
{
	BOOL bDoExtract = TRUE;
	BOOL bDoLV1Crypt = TRUE;
	BOOL bDoCleanup = FALSE;
	char szOption[MAX_PATH] = {0};
	char szFileName[MAX_PATH] = {0};
	char szFilePath[MAX_PATH] = {0};
	char szFullFileName[MAX_PATH] = {0};
	char szLV1Crypt[MAX_PATH] = {0};
	char szDoCleanup[MAX_PATH] = {0};
	uint8_t *erk = NULL;
	uint8_t *riv = NULL;
	uint8_t *in = NULL;
	uint8_t *lv1ldr = NULL;
	uint32_t lv1ldr_size = 0;
	uint32_t end_of_data = 0;
	uint32_t size = 0;
	uint32_t args_mask = 0x00;
	int i = 0;
	int index = 0;


	// assure we have minimum args supplied
	if (argc < 3) {
		usage(NULL);
	}


	/// default arguments
	strcpy_s(szOption, MAX_PATH, "export");
	strcpy_s(szLV1Crypt, MAX_PATH, "yes");
	strcpy_s(szFileName, MAX_PATH, DEFAULT_FILENAME);
	strcpy_s(szFilePath, MAX_PATH, DEFAULT_FILEPATH);
	bDoExtract = TRUE;
	bDoLV1Crypt = TRUE;
	bDoCleanup = FALSE;

	///////////////////////		MAIN ARG PARSING LOOP	/////////////////////////////
	//
	//
	for (i = 1; i < argc; i++)
	{
		switch ( index = select_string(argv[i]) ) {

			// "-option" argument
			case 0:
				memset(szOption, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-option");
				if ( argv[i+1][0] == '-' )
					usage("-option");

				strcpy_s(szOption, MAX_PATH, argv[i+1]);
				if ( _stricmp(szOption, "export") == 0 )
					bDoExtract = TRUE;
				else if ( _stricmp(szOption, "import") == 0 )
					bDoExtract = FALSE;
				else
					usage("-option");
				i++;
				args_mask |= 0x01;
				break;

			// "-filename" argument
			case 1:
				memset(szFileName, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-filename");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) <= 1) )
					usage("-filename");

				strcpy_s(szFileName, MAX_PATH, argv[i+1]);				
				i++;
				break;

			// "-filepath" argument
			case 2:
				memset(szFilePath, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-filepath");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) <= 1) )
					usage("-filepath");

				strcpy_s(szFilePath, MAX_PATH, argv[i+1]);				
				i++;
				break;

			// "-lv1crypt" argument
			case 3:
				memset(szLV1Crypt, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-lv1crypt");
				if ( (strlen(argv[i+1]) < 2) || (strlen(argv[i+1]) > 3) )
					usage("-lv1crypt");
				if ( argv[i+1][0] == '-' )
					usage("-lv1crypt");

				strcpy_s(szLV1Crypt, MAX_PATH, argv[i+1]);
				if ( _stricmp(szLV1Crypt, "yes") == 0 )
					bDoLV1Crypt = TRUE;
				else if ( _stricmp(szLV1Crypt, "no") == 0 )
					bDoLV1Crypt = FALSE;
				else
					usage("-lv1crypt");
				i++;				
				break;

			// "-cleanup" argument
			case 4:
				memset(szDoCleanup, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-cleanup");
				if ( (strlen(argv[i+1]) < 2) || (strlen(argv[i+1]) > 3) )
					usage("-cleanup");
				if ( argv[i+1][0] == '-' )
					usage("-cleanup");

				strcpy_s(szDoCleanup, MAX_PATH, argv[i+1]);
				if ( _stricmp(szDoCleanup, "yes") == 0 )
					bDoCleanup = TRUE;
				else if ( _stricmp(szDoCleanup, "no") == 0 )
					bDoCleanup = FALSE;
				else
					usage("-cleanup");
				i++;				
				break;

			default:
				printf("\nINVALID parameter specified:%s!\n", argv[i]);
				usage(NULL);
				break;

		} // end switch{}
	}
	//
	/////////////////////////////////////////////////////////////////////////////////////////

	// make sure min. arg of "-option" and param specified
	if ( (args_mask & 0x01) == 0)
		usage("-option");
		
	//load lv0.elf
	if ( sprintf_s(szFullFileName, MAX_PATH, "%s\\%s", szFilePath, szFileName) <= 0)
		goto exit;	

	// read file into buffer
	if ( read_entire_file(szFullFileName, (void **)&in, &size, SFC_BLOCK_SIZE) < 0 ) {
		printf("\nERROR: could not read_file:%s\n", szFileName);
		goto exit;
	}
	// verify ELF header at start of file
	if( be32(in) != ELF_HEADER_SIG ) {
		printf("FAIL: %s is not an elf file\n", szFileName);
		exit(1);
	}

	//find keys/data for lv1ldr crypto
	erk = set_data(in, 0x108);
	riv = set_data(in, 0x1B8);

	end_of_data = get_end_of_last_section(in);

	T1 = set_data(in, (uint32_t)be64(in + end_of_data - 0x18));
	B = (uint32_t *) set_data(in, (uint32_t)be64(in + end_of_data - 0x10));
	T2 = set_data(in, (uint32_t)be64(in + end_of_data - 0x8));

	//find lv1ldr
	lv1ldr = get_lv1ldr(in, size);
	lv1ldr_size = get_lv1ldr_size(in, size, (uint32_t)(lv1ldr - in));

	/*print_hex(erk, 0x10);
	print_hex(riv, 0x10);
	print_hex(T1, 0x10);
	print_hex(B, 0x10);
	print_hex(T2, 0x10);
	print_hex(lv1ldr, 0x10);
	printf("lv1ldr_size %x\n", lv1ldr_size);*/

	//decrypt lv1ldr, unless option to disable is yes
	if (bDoLV1Crypt == TRUE)
		crypt_lv1ldr(lv1ldr, lv1ldr_size, erk, riv);

	//check decrypted lv1ldr
	if(be32(lv1ldr) != SELF_HEADER_SIG) {
		printf("(de)crypt_lv1ldr failed\n");
		exit(1);
	}

	// if we are doing EXPORT, 
	// extract the loaders
	if (bDoExtract == TRUE) {			
		extract_ldrs(in, size, szFilePath);
	}	
	else 
	{
		// import loaders, and
		// encrypt LV1 if specified (default)
		import_ldrs(in, size, szFilePath);		
		if (bDoLV1Crypt == TRUE)
			crypt_lv1ldr(lv1ldr, lv1ldr_size, erk, riv);

		// write out the final file
		write_file(szFullFileName, in, size);

		// if cleanup specified, delete the 
		// exracted loaders
		if (bDoCleanup == TRUE)
		{
			for (i = 0; i < NUM_EMBEDDED_LDRS; i++) {
				sprintf_s(szFullFileName, MAX_PATH, "%s\\%s", szFilePath, g_pszLdrNames[i]);
				DeleteFileA(szFullFileName);	
			}
		}
	} // end import_ldrs
	

exit:
	// free the alloc'd memory
	free(in);

	return 0;
}