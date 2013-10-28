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
			printf("exported ldr:%s at 0x%x size 0x%x bytes\n", g_pszLdrNames[ldr], i, ldr_size);
			
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
uint32_t import_ldrs(uint8_t *in, uint8_t *out, uint32_t lv0_size, char* szInPath, uint32_t* plv1ldr_outsize)
{
	uint32_t org_ldr_size, import_size, i = 0;
	uint64_t org_auth_id = 0;
	uint64_t new_auth_id = 0;
	uint8_t *ldr = NULL;
	uint32_t result = 1;
	char szInFileName[MAX_PATH] = {0};		
	int found = 0;
	
	
	// iterate the binary, and process importing the 
	// actual loaders from disk	
	for(i=0; i<lv0_size; i+=4)
	{
		if(be32(in+i) == SELF_HEADER_SIG)
		{			
			//sprintf_s(name, MAX_PATH, "ldr_%i", j);
			sprintf_s(szInFileName, MAX_PATH, "%s\\%s", szInPath, g_pszLdrNames[found]);

			// calculate the current size of the ldr in this slot, 
			// and the current auth_id
			org_ldr_size = (uint32_t)(be64(in+i+0x10) + be64(in+i+0x18));
			org_auth_id = (uint64_t)be64(in+i+0x70);			

			// read in the new ldr from the file on disk
			if (read_entire_file(szInFileName, (void **)&ldr, &import_size, SFC_BLOCK_SIZE) < 0) {
				printf("\nERROR: read_file failed:%s", szInFileName);
				result = 0;
				goto exit;
			}			
			// if the AUTHID of the new ldr, does NOT match
			// the AUTHID of the original ldr, then fail out
			new_auth_id = (uint64_t)be64(ldr+0x70);
			if ( new_auth_id != org_auth_id ) {				
				printf("ERROR! AUTHIDs do NOT match!\n\t--> expected:0x%16llx, found:0x%16llx, file:%s\n", org_auth_id, new_auth_id, g_pszLdrNames[found]);
				result = 0;
				goto exit;
			}
			// check our imported ldr size, versus the original size of the
			// ldr that was in LV0.  If import_size is larger than the max size,
			// we must fail out
			if ( import_size > org_ldr_size ) {
				printf("import failed: file:%s is TOO LARGE! MAX size for import: 0x%x, size attempted: 0x%x\n", g_pszLdrNames[found], org_ldr_size, import_size);
				result = 0;
				goto exit;
			}
			else {								
				printf("imported ldr:%s at 0x%x, new size 0x%x (prev. size 0x%x)\n", g_pszLdrNames[found], i, import_size, org_ldr_size);
				// get the actual size of the "lv1ldr.self"
				if ( strstr(szInFileName, g_pszLdrNames[0]) != NULL )
					*plv1ldr_outsize = import_size;
				// zero out the area before the copy (original size)
				// memset(in+i, 0x00, org_ldr_size);	
				// copy in the new ldr (new size)
				memcpy(out+i, ldr, import_size);
				if (ldr != NULL) {
					free(ldr);
					ldr = NULL;
				}
			}						
			found++;
			if(found >= NUM_EMBEDDED_LDRS)
				break;
		} // if (SCE...)
	} // for (i = 0...)
exit:
	// free the alloc'd memory
	if (ldr != NULL)
		free(ldr);

	return result;
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
	uint32_t ptr_lv1ldr = reverse_binsearch64(in, size, va);
	//printf("va %x\n", va);	
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
	printf("\tYES:	do crypt of lv1ldr before import ** default **\n");
	printf("\tNO:	do NOT crypt lv1ldr before import\n\n");			
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
	uint8_t *out = NULL;
	uint8_t *lv1ldr = NULL;
	uint8_t *lv1ldr_out = NULL;
	uint32_t lv1ldr_size = 0;
	uint32_t end_of_data = 0;
	uint32_t lv0_size = 0;
	uint32_t lv1ldr_finalsize = 0;
	uint32_t lv0_size_verify = 0;
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

	/////////////////////////////////////////////////////////////////////////////////////
	//  in order to avoid issues with decrypting the lv1ldr to verify it, and then having
	//  decrypted data left over, make a copy of the file into a second buffer, which we
	//  will ONLY use for the final output file....
	//
	// read file into "in" buffer
	if ( read_entire_file(szFullFileName, (void **)&in, &lv0_size, SFC_BLOCK_SIZE) < 0 ) {
		printf("\nERROR: could not read_file:%s\n", szFileName);
		goto exit;
	}
	// read file into "out" buffer
	if ( read_entire_file(szFullFileName, (void **)&out, &lv0_size_verify, SFC_BLOCK_SIZE) < 0 ) {
		printf("\nERROR: could not read_file:%s\n", szFileName);
		goto exit;
	}
	/////////////////////////////////////////////////////////////////////////////////////////


	// double check we read the file in correctly both times!
	if ( lv0_size != lv0_size_verify ) {
		printf("FAIL: unexpected error reading in the LV0 file, please exit and try again!!!\n");
		goto exit;
	}
	// verify ELF header at start of file
	if( be32(in) != ELF_HEADER_SIG ) {
		printf("FAIL: %s is not an elf file\n", szFileName);
		goto exit;
	}

	//find keys/data for lv1ldr crypto
	erk = set_data(in, 0x108);
	riv = set_data(in, 0x1B8);

	end_of_data = get_end_of_last_section(in);

	T1 = set_data(in, (uint32_t)be64(in + end_of_data - 0x18));
	B = (uint32_t *) set_data(in, (uint32_t)be64(in + end_of_data - 0x10));
	T2 = set_data(in, (uint32_t)be64(in + end_of_data - 0x8));	

	//find lv1ldr, and get its' current size
	lv1ldr = get_lv1ldr(in, lv0_size);
	lv1ldr_size = get_lv1ldr_size(in, lv0_size, (uint32_t)(lv1ldr - in));
	//printf("lv1ldr:0x%p\n", lv1ldr);	

	/*print_hex(erk, 0x10);
	print_hex(riv, 0x10);
	print_hex(T1, 0x10);
	print_hex(B, 0x10);
	print_hex(T2, 0x10);
	print_hex(lv1ldr, 0x10);
	printf("lv1ldr_size %x\n", lv1ldr_size);*/	

	// first check the current lv1ldr, if it currently
	// exists in 'encrypted' state, decrypt it, so we can
	// read the headers during the 'import' phase
	if(be32(lv1ldr) != SELF_HEADER_SIG)
	{
		// do the decrypt of the lv1ldr
		crypt_lv1ldr(lv1ldr, lv1ldr_size, erk, riv);
		if(be32(lv1ldr) != SELF_HEADER_SIG) {
			printf("failed to verify header of lv1ldr\n");
			goto exit;
		}
		else
			printf("CRYPTED LV1LDR located/decrypted successfully\n");
	}
	else
		printf("NON-CRYPTED LV1LDR located successfully\n");

	// if we are doing EXPORT, 
	// extract the loaders
	if (bDoExtract == TRUE)
	{			
		// now extract the loaders
		extract_ldrs(in, lv0_size, szFilePath);
	}	
	else 
	{	
		// import in the new ldrs		
		if ( import_ldrs(in, out, lv0_size, szFilePath, &lv1ldr_finalsize) != 1)
			goto exit;

		// if we selected "lv1crypt", then encrypt the lv1ldr
		if (bDoLV1Crypt == TRUE) {
			// find lv1ldr, and get its' current size, 
			// and then crypt it
			lv1ldr_out = get_lv1ldr(out, lv0_size);			
			crypt_lv1ldr(lv1ldr_out, lv1ldr_finalsize, erk, riv);
			printf("\t*** lv1ldr set to ENCRYPTED (size:0x%x) ***\n", lv1ldr_finalsize);
		}
		else
			printf("\t*** lv1ldr set to NON-ENCRYPTED (size:0x%x) ***\n", lv1ldr_finalsize);

		// write out the final file
		write_file(szFullFileName, out, lv0_size);

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

	printf("\n\n!!! LV0TOOL SUCCESS !!!\n\n");

exit:
	// free the alloc'd memory
	if (in != NULL)
		free(in);

	// free the alloc'd memory
	if (out != NULL)
		free(out);

	return 0;
}