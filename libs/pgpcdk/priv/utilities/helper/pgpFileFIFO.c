/*
 * pgpFileFIFO.c
 * Use a disk file as a fifo.
 *
 * File grows indefinitely until fifo empties, at which pointers reset
 * to the beginning.  (File never shrinks though.)
 * So file size will be the maximum of the number of bytes written since
 * the previous time the fifo was empty.
 *
 * $Id: pgpFileFIFO.c,v 1.40 1998/12/15 07:59:50 heller Exp $
 */

#include "pgpConfig.h"

#include <stdio.h>	/* For BUFSIZ */

#include "pgpDebug.h"
#include "pgpCFBPriv.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpFIFO.h"
#include "pgpMem.h"
#include "pgpUsuals.h"
#include "pgpErrors.h"
#include "pgpRandomX9_17.h"
#include "pgpFileRef.h"
#include "pgpFileSpec.h"
#include "pgpContext.h"

#if (BUFSIZ < 16384) && (PGP_MACINTOSH || PGP_WIN32)
#define kPGPFIFOBufSize		16384
#else
#define kPGPFIFOBufSize		BUFSIZ
#endif

/* Use this cipher for encrypting data to disk.  */
#define DEFAULTCIPHER		kPGPCipherAlgorithm_3DES
/*
 * putoff is offset in file where next written byte will go
 * getoff is offset in file where next read byte will come from
 * peekoff-getoff is # bytes in buf we have read and decrypted
 */
struct PGPFifoContext {
	PGPContextRef	context;
	FILE *f;
	PFLFileSpecRef	fileRef;
	PGPByte *buf;
	PGPSize	 putoff, getoff, peekoff;
	PGPCFBContext *rdcfb, *wrcfb;
	DEBUG_STRUCT_CONSTRUCTOR( PGPFifoContext )
};

static void
fileFifoFlush(PGPFifoContext *fifo)
{
	fifo->putoff = 0;
	fifo->getoff = 0;
	fifo->peekoff = 0;
}

static PGPSize
fileFifoSize(PGPFifoContext const *fifo)
{
	return (PGPSize)(fifo->putoff - fifo->getoff);
}

static void
fileFifoFreeCfbs(PGPFifoContext *fifo)
{
	PGPFreeCFBContext(fifo->rdcfb);
	PGPFreeCFBContext(fifo->wrcfb);
}

/* Return negative on error, 0 on success */
static int
fileFifoInitCfbs(PGPFifoContext *fifo)
{
	PGPRandomContext *rc;
	PGPCipherVTBL const *cipher;
	PGPSize cfbkeysize;
	PGPByte *cfbkey;
	PGPByte cfbiv[PGP_CFB_MAXBLOCKSIZE];
	PGPContextRef	context;
	PGPError		err	= kPGPError_NoErr;
	
	pgpAssertAddrValid( fifo, PGPFifoContext );
	context	= fifo->context;

	/* XXX Interface doesn't provide env to choose dflt cipher */
	cipher = pgpCipherGetVTBL(DEFAULTCIPHER);
	if (!cipher) {
		return kPGPError_FeatureNotAvailable;
	}
	cfbkeysize = cipher->keysize;
	cfbkey = (PGPByte *)pgpContextMemAlloc( context,
		cfbkeysize, 0);
	if (!cfbkey)
		{
		return kPGPError_OutOfMemory;
	}
	rc = pgpRandomCreate( context );
	pgpAssert(rc);
	pgpRandomGetBytes(rc, cfbkey, cfbkeysize);
	pgpRandomGetBytes(rc, cfbiv, sizeof(cfbiv));
	pgpRandomDestroy(rc);
	fifo->rdcfb = pgpCFBCreate( PGPGetContextMemoryMgr( context ), cipher);
	PGPInitCFB(fifo->rdcfb, cfbkey, cfbiv);
	pgpClearMemory(cfbkey, cfbkeysize);
	pgpClearMemory(cfbiv, sizeof(cfbiv));
	pgpContextMemFree( context, cfbkey);

	err	= PGPCopyCFBContext( fifo->rdcfb, &fifo->wrcfb );
	if ( IsPGPError( err ) ) {
		fileFifoFreeCfbs(fifo);
		return err;
	}
	return( kPGPError_NoErr );
}

static PGPFifoContext *
fileFifoCreate( PGPContextRef	context )
{
	PGPFifoContext *fifo;
	PGPError err;

	fifo = (PGPFifoContext *)pgpContextMemAlloc(
			context, sizeof(*fifo), 0);
	if (!fifo)
		return NULL;
	fifo->context	= context;
	
	fifo->buf = (PGPByte *)pgpContextMemAlloc( context,
			kPGPFIFOBufSize, 0);
	if (!fifo->buf) {
		pgpContextMemFree( context, fifo);
		return NULL;
	}
	fifo->context	= context;
	
	if (fileFifoInitCfbs(fifo) < 0) {
		pgpContextMemFree( context, fifo->buf);
		pgpContextMemFree( context, fifo);
		return NULL;
	}
	fifo->f = pgpStdIOOpenTempFile( context, &fifo->fileRef, &err);
	if (!fifo->f) {
		fileFifoFreeCfbs(fifo);
		pgpContextMemFree(context, fifo->buf);
		pgpContextMemFree(context, fifo);
		return NULL;
	}
	fifo->putoff = 0;
	fifo->getoff = 0;
	fifo->peekoff = 0;
		
	return fifo;
}

static void
fileFifoDestroy(PGPFifoContext *fifo)
{
	fclose(fifo->f);
	if (fifo->fileRef != NULL)
	{
		PFLFileSpecDelete(fifo->fileRef);
		PFLFreeFileSpec(fifo->fileRef);
	}
	fileFifoFreeCfbs(fifo);
	pgpClearMemory(fifo->buf, kPGPFIFOBufSize);
	pgpContextMemFree( fifo->context, fifo->buf);
	pgpContextMemFree( fifo->context, fifo);
}


/* This could definitely use some optimizing */
static PGPByte const *
fileFifoPeek(PGPFifoContext *fifo, PGPSize *len)
{
	PGPSize dsklen;

	if (fifo->putoff == fifo->getoff) {
		*len = 0;
		return NULL;
	}

	if (fifo->peekoff > fifo->getoff) {
		/* Have peeked data in buffer already */
		*len = fifo->peekoff - fifo->getoff;
		return fifo->buf;
	}

	if (fifo->putoff - fifo->getoff > kPGPFIFOBufSize)
		dsklen = kPGPFIFOBufSize;
	else
		dsklen = (PGPSize)(fifo->putoff - fifo->getoff);

	if (fseek(fifo->f, fifo->getoff, SEEK_SET) != 0) {
		*len = 0;
		return NULL;
	}

	if (fread(fifo->buf, 1, dsklen, fifo->f) != dsklen) {
		*len = 0;
		return NULL;
	}

	pgpCFBDecryptInternal(fifo->rdcfb, fifo->buf, dsklen, fifo->buf);
	fifo->peekoff = fifo->getoff + dsklen;

	*len = dsklen;
	return fifo->buf;
}

static void
fileFifoSeek(PGPFifoContext *fifo, PGPSize len)
{
	if (!len)
		return;

	pgpAssert(fifo->putoff - fifo->getoff >= (PGPSize)len);
	pgpAssert(fifo->peekoff - fifo->getoff >= (PGPSize)len);
	pgpAssert(fifo->putoff >= fifo->peekoff);

	fifo->getoff += len;
	if (fifo->getoff < fifo->peekoff) {
		/* Move data in fifo down */
		pgpCopyMemory(fifo->buf+len, fifo->buf, fifo->peekoff-fifo->getoff);
	}

	/* If fifo becomes empty, reset pointers to beginning of file */
	if (fifo->putoff == fifo->getoff)
		fifo->putoff = fifo->getoff = fifo->peekoff = 0;
}

static size_t
fileFifoWrite(PGPFifoContext *fifo, PGPByte const *buf, size_t len)
{
	size_t lenleft;
	size_t buflen;

	if (fseek(fifo->f, fifo->putoff, SEEK_SET) != 0)
		return kPGPError_FileOpFailed;
	lenleft = len;
	while (lenleft) {
		buflen = (lenleft < kPGPFIFOBufSize) ? lenleft : kPGPFIFOBufSize;
		pgpCFBEncryptInternal(fifo->wrcfb, buf, buflen, fifo->buf);
		if (fwrite(fifo->buf, 1, buflen, fifo->f) != buflen)
			return kPGPError_WriteFailed;
		buf += buflen;
		lenleft -= buflen;
		fifo->putoff += buflen;
	}
	return len;
}

static size_t
fileFifoRead(PGPFifoContext *fifo, PGPByte *buf, size_t len)
{
	size_t avail;

	/* First get data out of peekahead buffer if any */
	if (fifo->peekoff > fifo->getoff) {
		avail = fifo->peekoff - fifo->getoff;
		if (avail > len)
			avail = len;
		pgpCopyMemory(fifo->buf, buf, avail);
		len -= avail;
		buf += avail;
		fifo->getoff += avail;
		if (fifo->peekoff > fifo->getoff) {
			/* Move data in fifo down */
			pgpCopyMemory(fifo->buf+avail, fifo->buf,
			       fifo->peekoff-fifo->getoff);
		}
		if (len == 0)
			return avail;
	}

	avail = fifo->putoff - fifo->getoff;
	if (avail > len)
		avail = len;

	if (fseek(fifo->f, fifo->getoff, SEEK_SET) != 0)
		return kPGPError_FileOpFailed;
	if (fread(buf, 1, avail, fifo->f) != avail)
		return kPGPError_ReadFailed;

	pgpCFBDecryptInternal(fifo->rdcfb, buf, avail, buf);
	
	fifo->getoff += avail;
	if (fifo->putoff == fifo->getoff)
		fifo->putoff = fifo->getoff = 0;

	return avail;
}

PGPFifoDesc const pgpFileFifoDesc = {
	"File Fifo",
	fileFifoCreate,
	fileFifoRead,
	fileFifoWrite,
	fileFifoPeek,
	fileFifoSeek,
	fileFifoFlush,
	fileFifoDestroy,
	fileFifoSize
};
