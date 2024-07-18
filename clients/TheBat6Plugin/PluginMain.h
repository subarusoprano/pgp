
long WINAPI pgp60_add_key(
		    HWND   hWndParent,
		    char* szBuffer,
                    DWORD dwInSize);

long WINAPI pgp60_decode(HWND hwndParent,
                    char*  Source,
                    DWORD  srcSize,
                    char** Dest,
                    DWORD* ResultSize,
		    BOOL*  FYEO);

long WINAPI pgp60_encode(
		    HWND hWndParent,
                    char** Rcpts,
                    DWORD  nRcpts,
                    BOOL   bEncrypt,
                    BOOL   bSign,
                    char*  Source,
                    DWORD  srcSize,
                    char** Dest,
                    DWORD* ResultSize,
		    BOOL   bBinary);

void WINAPI pgp60_free(void *m);

BOOL WINAPI pgp60_defencrypt(void);

BOOL WINAPI pgp60_defsign(void);

long WINAPI pgp60_init(void);
long WINAPI pgp60_finish(void);
long WINAPI pgp60_config(void);
long WINAPI pgp60_launch_keys(void);
