/*
 * pgpPrsBin.c -- Binary Parser
 *
 * Written by:	Colin Plumb and Derek Atkins <warlord@MIT.EDU>
 *
 * $Id: pgpPrsBin.c,v 1.65 1999/04/14 18:51:26 hal Exp $
 */
#include "pgpConfig.h"

#include <stdio.h>
#include <string.h>

#include "pgpDebug.h"
#include "pgpPktByte.h"
#include "pgpPrsAsc.h"
#include "pgpPrsBin.h"
#include "pgpAnnotate.h"
#include "pgpCFBPriv.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpCiphrMod.h"
#include "pgpCompress.h"
#include "pgpCompMod.h"
#include "pgpEncodePriv.h"
#include "pgpFIFO.h"
#include "pgpHashPriv.h"
#include "pgpHashMod.h"
#include "pgpHeader.h"
#include "pgpMem.h"
#include "pgpEnv.h"
#include "pgpErrors.h"
#include "pgpPipeline.h"
#include "pgpSig.h"
#include "pgpTextFilt.h"
#include "pgpUsuals.h"
#include "pgpContext.h"

#define PARSERMAGIC	0xfeedf00d

/* Only accept this much data per call to parsePacket */
#define PARSER_SIZE_LIMIT	512

/*
 * There are two formats for PGP packets.  Both are equivalent as far as
 * the rest of the code is concerned.
 * The original PGP packet format:
 * - Packet byte: 10ttttll, where tttt = packet type, and ll = length of length
 * - Length field, 1/2/4/0 bytes, big-endian, based on ll bits
 * - Body
 * This format is simple and small, but requires knowing the size of the
 * enclosed data before you can emit the length field.
 *
 * The one-pass PGP 3 format:
 * - Packet byte 11tttttt, where tttttt = packet type
 * - Zero or more non-final subpackets, starting with a byte of the form
 *   111sssss, followed by 2^s bytes of data
 * - A final subpacket, which starts with either 0sssssss, 10sssssss,
 *   or 110sssss ssssssss, holding up to 2^7 + 2^6 + 2^13 - 1 bytes.
 *   (The formats encode lengths of 0-127, 128-191, and 192-8383 bytes.)
 *
 * Generally, a PGP implementation will emit non-final subpackets in the
 * 1K to 8K range, followed by one final subpacket.  However, any size
 * may be used, down to one byte.  This flexibility allows data to be
 * flushed out and a stream to be brought up to date at any byte boundary
 * by emitting a combination of non-final subpackets which sum to the
 * desired boundary.
 *
 * To keep track of both of these formats, there is a Header,
 * which describes the parsing state of the current subpacket header on
 * an arbitrary byte boundary.  It has three members:
 * lenbytes - the count of the number of bytes remaining in the
 *            current big-endian subpacket size.  This may be as large
 *            as 4.  As additional bytes are read, lenbytes is decremented
 *            and "pktlen" is increased with the appropriately shifted
 *            byte.
 * more - a flag which is true if the current subpacket is non-terminal,
 *        so another subpacket is expected.
 * pktlen - the length of the current subpacket.  If lenbytes is non-zero,
 *          the value here is an underestimate.  When this is 0, a new
 *          packet or subpacket (depending on the more flag) is expected.
 * 
 * To keep track of the state of the input stream, a Header structure is
 * used, but data that has already been read from the Header structure
 * is kept around as well.  There are two data structures for this:
 * - The FIFO contains a copy of the raw input data up to the point
 *   marked by "passptr".
 * - The buffer, which also holds a prefix of the input data, but a
 *   parsed version.  A portion of the two overlap, and what can be
 *   kept in the buffer, is.  This always includes the tail of the last
 *   subpacket that has been read.  If this is also the first subpacket,
 *   nothing actually needs to get copied to the FIFO at all.
 *
 * The buffer ends up looking like this:
 *
 * /------------------------ passptr - First byte not passed through to FIFO.
 * |
 * v
 * +------------------------------------+
 * |                                    |
 * +------------------------------------+
 *     ^           ^
 *     |           |
 *     |           \--------- bufend - End of packet header/start of read-ahead
 *     \--------------------- bufptr - Beginning of intra-packet header
 * 
 * It works like this: The data from the FIFO, plus passptr through bufend,
 * is the raw data that's been processed.  Passptr is usually before
 * bufptr, with the gap filled by the packet's external header
 * (packet header byte plus length or first subpacket header), and
 * then bufptr through bufend is shared between the two.
 *
 * If the amount of header data needed exceeds the size of the first
 * subpacket, then the data up to and including the second subpacket
 * header is copied to the FIFO, and as much of the second subpacket as
 * is needed is read into the buffer immediately following the first
 * subpacket, with no intervening subpacket header, and "passptr" is
 * set to point to the beginning of the second subpacket data.
 *
 * The data between bufend and readptr is, however, raw input data
 * including subpacket headers that have not yet been parsed.
 */

/* Size of buffer - must hold a whole ESK or SIG packet */
/* 4096 bit ElGamal ESK's will be a bit over 1024 bytes */
/* Some X.509 sigs can be several times this */
/* However this is OK, they are only in keyring and get passed through */

//BEGIN RSA KEYSIZE MOD - Imad R. Faiad
//#define MAXPKTSIZE		1100
#define MAXPKTSIZE		4096
//END RSA KEYSIZE MOD


static size_t nextScope (PGPPipeline *myself, PGPByte const *buf,
			 size_t size, PGPError *error);
static size_t nextESK (PGPPipeline *myself, PGPByte const *buf,
		       size_t size, PGPError *error);
static size_t parsePacket (PGPPipeline *myself, PGPByte const *buf,
			   size_t size, PGPError *error);
static size_t parseKey (PGPPipeline *myself, PGPByte const *buf,
			size_t size, PGPError *error);

/* Used to recognize the beginning of a recursive literal packet */
static char const pgp_message_begin[] = "-----BEGIN PGP ";


/* Information needed to parse a subpacket header */
typedef struct Header {
	PGPUInt32 pktlen;		/* Length of current subpacket */
	unsigned lenbytes;	/* Number of length bytes to come */
	PGPByte more;		/* More subpackets to come */
} Header;

/* Information needed to parse a data stream */
typedef struct Input {
	PGPByte buffer[MAXPKTSIZE];	/* Buffer of parsed data */
	PGPFifoContext *fifo;	/* FIFO of raw data */
	PGPByte const *passptr;	/* Pointer into buffer */
	PGPByte const *bufptr;	/* Pointer into buffer */
	PGPByte *bufend;		/* Pointer into buffer */
	Header head;	/* Current subpacket status */
	PGPByte silent_trunc;	/* Complain if out of input? */
} Input;

typedef struct PrsBinContext {
	PGPPipeline		pipe;
	
	Input input;
	PGPPipeline *tail;
	PGPPipeline *nextparser;
	PGPPipeline **end;
	PGPHashListRef hashes;
	PGPEnv const *env;
	int state;		/* Used my bumerous parse functions */
	int end_scope;		/* Annotation at end of this scope, or 0 */
	PGPByte subtype;		/* Type of literal packet (t vs. b) */
	int sig1pass;		/* Within 1-pass signature scope */
	int sig1nest;		/* Number of unpaired 1pass headers nested */
	/* Flags */
	PGPByte sepsig;		/* 1-pass separate signature */
	PGPByte findpkt;		/* Searching for a new packet */
	PGPByte eof;		/* No more input available, ever */
	PGPByte needcallback;
	PGPByte nopurge;	/* Suppress purge of input buffer */
	PGPUICb const *ui;
	void *ui_arg;
	//BEGIN MDC PACKET SUPPORT - Disastry
	PGPBoolean		bIsMDC;
	//END MDC PACKET SUPPORT
	DEBUG_STRUCT_CONSTRUCTOR( PrsBinContext )
} PrsBinContext;

/* Return true if the end of the current packet has been reached */
static int
inputFinished(Header const *head)
{
	return !head->pktlen && !head->lenbytes && !head->more;
}

/*
 * Return a pointer to, and then length of, the subpacket header at the
 * current position in the input buffer, using the context of "head".
 */
static PGPByte const *
inputHeadPeek(Header const *head, PGPByte const *buf, size_t size,
              size_t *len)
{
	pgpAssert(buf || !size);

	if (head->lenbytes) {
		*len = (size < head->lenbytes) ? size : (size_t)head->lenbytes;
		return buf;
	}
	if (head->pktlen) {
		*len = 0;
		return buf;
	}
	if (!head->more) {
		*len = 0;
		return (PGPByte const *)0;
	}
	if (!size) {
		*len = 0;
		return buf;
	}
	if (buf[0] == 0xff && size >= 5)
		*len = 5;
	else if (buf[0] == 0xff)
		*len = size;
	else if ((buf[0] & 0xe0) == 0xc0 && size > 1)
		*len = 2;
	else
		*len = 1;
	return buf;
}

/*
 * Skip the upcoming header, adjusting the state in "head" appropriately.
 * Return the number of bytes consumed (<= size).
 */
static size_t
inputHeadSeek(Header *head, PGPByte const *buf, size_t size)
{
	unsigned i;
	unsigned char b;

	/* No data, don't care */
	if (!size)
		return 0;
	pgpAssert(buf);

	/* If we're in the middle of a header, read the tail of it */
	if (head->lenbytes) {
		if (size > head->lenbytes)
			size = (size_t)head->lenbytes;
		i = (unsigned)size;
		do {
			head->pktlen += (PGPUInt32)*buf++ << (8*--head->lenbytes);
		} while (--i);
		return size;
	}

	/* Are we not at the end of a packet? */
	if (head->pktlen || !head->more)
		return 0;

	/* Otherwise, we're starting a new subpacket header */
	b = buf[0];
	if (b < 0xc0) {
		head->pktlen = (PGPUInt32)b;
		head->more = 0;
	} else if (b < 0xe0) {
		head->pktlen = ((PGPUInt32)b << 8) - (0xc000 - 0xc0);
		head->more = 0;
		if (size == 1) {
			head->lenbytes = 1;
		} else {
			head->pktlen += (PGPUInt32)buf[1];
			return 2;
		}
	} else if (b == 0xff) {
		if (size > 5)
			size = 5;
		i = (unsigned)size-1;
		head->more = 0;
		head->lenbytes = 4;
		head->pktlen = 0;
		do {
			head->pktlen += (PGPUInt32)*++buf << (8*--head->lenbytes);
		} while (--i);
		return size;
	} else if (b >= 0xe0) {
		head->pktlen = (PGPUInt32)1 << (b & 31);
	}
	return 1;
}
                
static void
inputReset(Input *input)
{
	input->passptr = input->bufptr = input->bufend = input->buffer;
	input->head.pktlen = 0;
	input->head.lenbytes = 0;
	input->head.more = 0;
}

/*
 * Start parsing a packet with the given header byte.
 * Returns 0 if it's a normal, good header byte, and -1
 * if it's a bogus header byte, in which case the rest of the
 * input is taken as the body.
 */
static int
inputStart(Input *input, PGPByte b)
{
	/* Store first byte in buffer */
	input->passptr = input->buffer;
	input->buffer[0] = b;
	input->bufend = input->buffer+1;
	input->head.pktlen = 0;

	if (IS_NEW_PKTBYTE(b)) {
		/* New style */
		input->head.lenbytes = 0;
		input->head.more = 1;
		input->silent_trunc = 0;
	} else if (IS_OLD_PKTBYTE(b)) {
		/* Old style */
		input->head.lenbytes = LLEN_TO_BYTES(PKTBYTE_LLEN(b));
		input->head.more = 0;
		input->silent_trunc = 0;
		if (PKTBYTE_LLEN(b) == 3) {
			input->silent_trunc = 1;
			input->head.pktlen = (PGPUInt32)-1;
		}
	} else {
		/* Erroneous! */
		input->bufptr = input->buffer;
		input->head.pktlen = (PGPUInt32)-1;
		input->head.lenbytes = 0;
		input->head.more = 0;
		input->silent_trunc = 1;
		return -1;
	}
	/* Usual case wrapup */
	input->bufptr = input->bufend;
	return 0;
}

/*
 * Return a pointer to, and the length of, the next available packet payload
 * bytes.  These bytes will come from either the read-ahead buffer or the
 * input buffer (buf, size), as appropriate.  Returns a NULL pointer when
 * there is no more data available in the packet.  If "size" is 0 and
 * this is not the end of the packet, this returns the "buf" pointer,
 * which may or may not be NULL, at the caller's discretion.
 *
 * This may, in some situations (like when "size" is 1 and sitting
 * on a subpacket header), return the "buf" pointer but a zero length
 * even when size is non-zero.
 * In that case, the current packet is not finished, but no data is available
 * in the current input buffer.   You need to call inputSeek(0) to give
 * it a chance to consume the current input buffer.
 */
static PGPByte const *
inputPeek(Input const *input, PGPByte const *buf, size_t size, size_t *len)
{
	/* If we have no buffer, then size must be 0 */
	pgpAssert(buf || !size);

	/* If we have data buffered, use that. */
	if (input->bufend != input->bufptr) {
		*len = (size_t)(input->bufend - input->bufptr);
		return input->bufptr;
	}
	/*
	 * If we are in the middle of a subpacket header, no data available,
	 * but more to come.
	 */
	if (input->head.lenbytes) {
		*len = 0;
		return buf;
	}
	/*
	 * If we're at the end of a subpacket, no data available, and
	 * there may or may not be more to come.
	 */
	if (!input->head.pktlen) {
		*len = 0;
		return input->head.more ? buf : 0;
	}

	/* Return the appropriate data from the input buffer */
	if (size > input->head.pktlen)
		size = (size_t)input->head.pktlen;

	*len = size;
	return buf;
}

/*
 * Skip over "len" bytes (where len <= the amount returned from the latest
 * call to inputPeek!) of input from the input stream (either the context
 * buffer or the supplied external buffer).
 */
static size_t
inputSeek(Input *input, PGPByte const *buf, size_t size, size_t len)
{
	pgpAssert(buf || !size);

	/* If we have data in the input buffer, skip that */
	if (input->bufend != input->bufptr) {
		pgpAssert(len <= (size_t)(input->bufend - input->bufptr));
		input->bufptr += len;
		return 0;
	}
	/* Make sure the skip is legal */
	pgpAssert(!len || !input->head.lenbytes);
	pgpAssert(len <= input->head.pktlen);
	pgpAssert(len <= size);

	/* Skip the data */
	input->head.pktlen -= len;

	/* Skip any additional header that follows */
	return len + inputHeadSeek(&input->head, buf+len, size-len);
}

/*
 * Copy the input buffer to the FIFO.
 */
static PGPError
inputToFifo(Input *input)
{
	size_t len, written;

	len = (size_t)(input->bufend - input->passptr);
	if (len) {
		written = pgpFifoWrite (&pgpByteFifoDesc, input->fifo,
					input->passptr, len);
		input->passptr += written;
		if (written != len)
			return kPGPError_OutOfMemory;
	}
	return( kPGPError_NoErr );
}

/*
 * Try to ensure that the next "desired" bytes of input are contiguous
 * and thus inputPeek will return them in one call.  This will copy
 * bytes from the external buffer to the input buffer.  If it does,
 * the number of bytes copied is returned.
 *
 * If this needs to squeeze subpacket header bytes out of the read-ahead
 * buffer to make the buffer contiguous, it copies the bytes to the FIFO
 * so they'll be available for raw reading.
 */
static size_t
inputMerge(Input *input, PGPByte const *buf, size_t size, unsigned desired,
           PGPError *error)
{
	size_t size0;
	size_t s, t;
	unsigned avail;

	pgpAssert(buf || !size);

	*error = kPGPError_NoErr;	/* No error */

	s = (size_t)(input->bufend - input->bufptr);
	if (s >= desired)
		return 0;
	desired -= (unsigned)s;

	size0 = size;
	
	while (desired && size) {
		/* Suck in the following header, if any */
		if (!inputHeadPeek(&input->head, buf, size, &s))
			break;	/* End of packet */
		/* If we have a header, deal with it. */
		if (s) {
			/*
			 * Do something with the header - put it in the buffer
			 * before bufptr if possible, or in the FIFO if not.
			 */
			if (input->bufptr == input->bufend) {
				memcpy(input->bufend, buf, s);
				(void)inputHeadSeek(&input->head, buf, s);
				input->bufptr = input->bufend += s;
				buf += s;
				size -= s;
			} else {
				/* Write what's already in the buffer */
				*error = inputToFifo(input);
				if (*error)
					break;
				/* Write the current header to the FIFO */
				t = pgpFifoWrite (&pgpByteFifoDesc,
						  input->fifo, buf, s);
				(void)inputHeadSeek(&input->head, buf, t);
				buf += t;
				size -= t;
				if (t != s) {
					*error = kPGPError_OutOfMemory;
					break;
				}
			}
		}

		/* Normal data to be copied */
		avail = desired;
		if (avail > size)
			avail = (unsigned)size;
		if (avail > input->head.pktlen)
			avail = (unsigned)input->head.pktlen;
		s = input->buffer+sizeof(input->buffer)-input->bufend;
		if (avail > s) {
			if (!s)
				break;
			avail = (unsigned)s;
		}
		memcpy(input->bufend, buf, avail);
		input->bufend += avail;
		input->head.pktlen -= avail;
		size -= avail;
		desired -= avail;
	}

	return size0-size;
}

/* Return true if there's more packet in here than will fit */
static int
inputOverfull(Input const *input)
{
	return input->bufend == input->buffer+sizeof(input->buffer) &&
		!inputFinished(&input->head);
}

/* How many merged bytes are available? */
static size_t 
inputMerged(Input const *input)
{
	return (size_t)(input->bufend - input->bufptr);
}

/* Pointer to the merged bytes */
static unsigned char const *
inputMergedPtr(Input const *input)
{
	return input->bufptr;
}

/*
 * Return a buffer and length corresponding to the next batch of
 * raw (unparsed) characters in the current packet.
 * The bytes might come from one of three places:
 * - The FIFO where they have been copied by inputMerge()
 * - The input buffer
 * - the passed-in external buffer
 * In the latter case, this parses ahead in the input buffer as many
 * subpackets as possible to give the largest block of data possible.
 *
 * Returns NULL with a length of 0 if there are no more bytes in the current
 * packet.  Returns "buf" with a length of 0 if size is 0.
 * That may or may not be NULL, depending on the caller.
 */
static PGPByte const *
inputRawPeek(Input const *input, PGPByte const *buf, size_t size,
             size_t *len)
{
	PGPByte const *p;
	size_t s;
	size_t size0;
	PGPSize ulen;
	Header head;

	pgpAssert(buf || !size);
	
	/* Try the byte FIFO */
	p = pgpFifoPeek (&pgpByteFifoDesc, input->fifo, &ulen);
	if (p) {
		*len = (size_t)ulen;
		return p;
	}
	/* Then the buffered data */
	if (input->passptr != input->bufend) {
		*len = input->bufend - input->passptr;
		return input->passptr;
	}
	/* Finally, the external buffer */

	size0 = size;
	p = buf;
	head = input->head;

	while (size && !inputFinished(&head)) {
		s = inputHeadSeek(&head, p, size);
		size -= s;
		if (!size)
			break;
		p += s;
		if (size <= head.pktlen) {
			size = 0;
			break;
		}
		size -= head.pktlen;
		p += head.pktlen;
		head.pktlen = 0;
	}

	*len = size0 - size;
	return buf;
}

/*
 * Skip forward over a given number of bytes of raw input data.
 * The number of bytes must be <= the number returned from
 * inputRawPeek().
 *
 * The FIFO and buffered data are simple.  If those are empty,
 * parse forward in the external buffer until the desired number of
 * bytes have been skipped, then store the parsing state.
 */
static size_t
inputRawSeek(Input *input, PGPByte const *buf, size_t size, unsigned len)
{
	size_t s;

	pgpAssert(buf || !size);
	
	/* If there's data in the FIFO, skip that... */
	if (pgpFifoSize (&pgpByteFifoDesc, input->fifo)) {
		pgpFifoSeek (&pgpByteFifoDesc, input->fifo, len);
		return 0;
	}
	/* Otherwise the buffered data */
	if (input->passptr != input->bufend) {
		pgpAssert(len <= (size_t)(input->bufend - input->passptr));
		input->passptr += len;
		if (input->bufptr < input->passptr)
			input->bufptr = input->passptr;
		return 0;
	}

	/* Finally, the external buffer */
	pgpAssert(len <= size);

	size = len;
	while (size) {
		s = inputHeadSeek(&input->head, buf, size);
		size -= s;
		if (!len)
			break;
		buf += s;
		if (size <= input->head.pktlen) {
			input->head.pktlen -= size;
			break;
		}
		size -= input->head.pktlen;
		buf += input->head.pktlen;
		input->head.pktlen = 0;
	}
	return len;
}

/* Get rid of the header we've processed from the system. */
static void
inputPurge(Input *input)
{
	pgpFifoFlush (&pgpByteFifoDesc, input->fifo);
	input->passptr = input->bufptr = input->bufend = input->buffer;
}


#if 0
/*
 * Write all the already-buffered bytes from the current packet.
 * Return an error, if any is encountered.
 */
static int
DoRawFlush (PrsBinContext *ctx, PGPPipeline *tail)
{
	PGPError	error = kPGPError_NoErr;
	size_t len;
	PGPByte const *p;

	do {
		p = inputRawPeek(&ctx->input, NULL, 0, &len);
		if (!p)
			break;
		len = tail->write (tail, p, len, &error);
		(void)inputRawSeek(&ctx->input, NULL, 0, len);
	} while (!error);

	return error;
}
#endif


static size_t
DoSkip (PGPPipeline *myself, PGPByte const *buf, size_t size, PGPError *error)
{
	PrsBinContext *ctx;
	size_t size0 = size;
	PGPByte const *p;
	size_t len;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	inputPurge (&ctx->input);

	for (;;) {
		p = inputPeek(&ctx->input, buf, size, &len);
		if (!p) {
			if (inputFinished(&ctx->input.head)) {
				/* End of input */
				myself->write = nextScope;
				size -= nextScope (myself, buf, size, error);
			}
			break;
		}
		if (!len && !size)
			break;
		len = inputSeek(&ctx->input, buf, size, len);
		size -= len;
		buf += len;
	}

	return size0-size;
}

/*
 * Write out the as-yet-unread body of this packet to the tail of this module.
 * At the end of the packet (inputFinished), set the state back to
 * nextScope.
 */
static size_t
DoWrite (PGPPipeline *myself, PGPByte const *buf, size_t size, PGPError *error)
{
	PrsBinContext *ctx;
	size_t len;
	size_t size0 = size;
	PGPByte const *p;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	do {
		p = inputPeek(&ctx->input, buf, size, &len);
		if (!p) {
			if (inputFinished(&ctx->input.head)) {
				/* End of input */
				myself->write = nextScope;
				size -= nextScope (myself, buf, size, error);
			}
			break;
		}
		if (!len && !size)
			break;
		len = ctx->tail->write (ctx->tail, p, len, error);
		len = inputSeek(&ctx->input, buf, size, len);
		size -= len;
		buf += len;
	} while (!*error);

	return size0-size;
}


/*
 * Write out a series of packets to the tail of this module, keeping
 * track of packet boundaries, and counting pairs of signature headers
 * and footers.  When come to an unpaired footer, exit to process it.
 */
static size_t
DoWriteSignedPackets(PGPPipeline *myself, PGPByte const *buf, size_t size,
	       PGPError *error)
{
	PrsBinContext *ctx;
	size_t len;
	size_t size0 = size;
	PGPByte const *p;
	PGPByte b;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
		/* Here at the start of a packet */

		inputReset(&ctx->input);

		if (!size)
			return 0;	/* I need a packet header! */

		/*
		 * Track signature nesting.
		 * sig1nest holds the excess 1pass sig hdrs we've seen
		 * We distinguish old-style sig packets from new style by
		 * whether the packet type byte is old or new style.
		 */
		if (IS_NEW_PKTBYTE(buf[0])) {
			PGPByte bt = PKTBYTE_TYPE(buf[0]);
			if (bt==PKTBYTE_SIG && ctx->sig1nest==0) {
				/* This footer is what we are looking for */
				myself->write = nextScope;
				size -= nextScope (myself, buf, size, error);
				break;
			} else if (bt==PKTBYTE_1PASSSIG) { /* sig header */
				++ctx->sig1nest;
			} else if (bt==PKTBYTE_SIG) { /* sig footer */
				--ctx->sig1nest;
			}
		}

		/* Else read and pass on this packet */
		b = *(buf++);
		size--;

		if (inputStart(&ctx->input, b) < 0) {
			pgpAssert (0);	/* what to do here? */
		}


		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		while (!inputFinished(&ctx->input.head)) {
			p = inputRawPeek(&ctx->input, buf, size, &len);
			if (!len)
				return size0-size;
			len = ctx->tail->write(ctx->tail, p, len, error);
			len = inputRawSeek(&ctx->input, buf, size, len);
			size -= len;
			buf += len;
			if (*error)
				return size0-size;
		}
		/* Here at end of packet */
		ctx->state = 0;
		break;
	}
		
	return size0-size;
}


/*
 * This function flushes the raw header bytes from the beginning of
 * the parser's buffer "over" the following module on to the following
 * parser, then falls through to writing the payload bytes to the following
 * module and the header bytes "over" it.
 */
static size_t
DoWriteNext (PGPPipeline *myself, PGPByte const *buf, size_t size,
	     PGPError *error)
{
	PrsBinContext *ctx;
	PGPByte const *p;
	size_t size0 = size;
	size_t len;
	PGPPipeline *tail, *next;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (ctx->nextparser);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	next = ctx->nextparser;
	*error = kPGPError_NoErr;

	for (;;) {
		p = inputRawPeek(&ctx->input, NULL, 0, &len);
		if (!len)
			break;
		len = next->write (next, p, len, error);
		(void)inputRawSeek(&ctx->input, NULL, 0, len);
		if (*error)
			return 0;
	}

	tail = ctx->tail;
	do {
		p = inputHeadPeek(&ctx->input.head, buf, size, &len);
		if (len) {
			len = next->write(next, p, len, error);
			(void)inputHeadSeek(&ctx->input.head, buf, len);
			buf += len;
			size -= len;
		} else {
			p = inputPeek(&ctx->input, buf, size, &len);
			if (len) {
				len = tail->write(tail, p, len, error);
				/* Note double "len" to prevent header skip */
				len = inputSeek(&ctx->input, buf, len, len);
				buf += len;
				size -= len;
			} else
				break;
		}
		if (*error)
			return size0-size;
	} while (size);

	/* If that's the end of this packet, continue with the next. */
	if (inputFinished(&ctx->input.head)) {
		/* End of input */
		myself->write = nextScope;
		size -= nextScope (myself, buf, size, error);
	}

	return size0-size;
}

/*
 * This function is called when we are checking the signature on a literal
 * packet.  The reason it is needed is that signatures are only on the BODY
 * of the literal packet, not the headers.  OOPS.  So find the size of
 * the literal packet header and pass it (external header and internal
 * header) "over" the hash module to the ctx->nextparser using
 * DoWriteNext.
 *
 * This does NOT report errors on a short or truncated literal packet, since
 * we're pretending not to be parsing it - the downstream parser will
 * notice it and do any necessary complaining.  It DOES, however, try
 * to write out such packets to the downstream parser so it can do the
 * reporting.
 */
static size_t
parseSignedLiteralMagic (PGPPipeline *myself,
                         PGPByte const *buf, size_t size, PGPError *error)
{
	PrsBinContext *ctx;
	size_t len;
	PGPByte const *p;
	size_t size0 = size;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	/* Make sure nothing confusing can happen here! */
	pgpAssert(!ctx->needcallback);

	/* Do NOT complain on truncation. */
	ctx->input.silent_trunc = 1;

	/* No error until told otherwise */
	*error = kPGPError_NoErr;

	switch (ctx->state) {
	  case 0:	/* Get packet header byte */
		if (!size)
			return 0;

		/* We know it's a literal packet, so no worries. */
		(void)inputStart(&ctx->input, *buf);
		buf++;
		size--;
		ctx->state++;
		/* FALLTHROUGH */
	  case 1:	/* Get internal header */
		len = inputMerge(&ctx->input, buf, size, 2, error);
		buf += len;
		size -= len;
		if (*error)
			break;
		p = inputPeek(&ctx->input, NULL, 0, &len);
		if (len < 2) {
			if (!inputFinished(&ctx->input.head))
				break;
		} else {
			len = inputMerge(&ctx->input, buf, size, 6+p[1],
					error);
			buf += len;
			size -= len;
			if (*error)
				break;
			if (inputMerged(&ctx->input) < (size_t)6+p[1]) {
				if (!inputFinished(&ctx->input.head))
					break;
			}
		}
		/* We've got as much as we need */
		ctx->state++;
		myself->write = DoWriteNext;
		size -= DoWriteNext (myself, buf, size, error);
		break;
	  default:
		pgpAssert(0);
	}
	return size0-size;
}

/*
 * This function just does a little bit of trivial initialization,
 * including setting the state to 0, and then falls through to
 * parseSignedLiteralMagic.  The Do functions can be called from a
 * variety of states, due to the way they are set up from callbacks
 * that may be called from a variety of states, so they can't depend on
 * the ctx->state.  Thus, the need for this little wrapper function.
 */
static size_t
DoSignedLiteralMagic (PGPPipeline *myself, PGPByte const *buf, size_t size,
		      PGPError *error)
{
	PrsBinContext *ctx;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	/* Make sure nothing confusing can happen here! */
	pgpAssert(!ctx->needcallback);

	/* Do NOT complain on truncation. */
	ctx->input.silent_trunc = 1;
	/* Reset state for parseSignedLiteralMagic */
	ctx->state = 0;
	myself->write = parseSignedLiteralMagic;
	return parseSignedLiteralMagic(myself, buf, size, error);
}

/*
 * Pass through the full ciphertext of the current packet, headers and
 * all, to the tail module
 */
static size_t
DoPassthrough (PGPPipeline *myself, PGPByte const *buf, size_t size,
	       PGPError *error)
{
	PrsBinContext *ctx;
	size_t size0 = size;
	PGPByte const *p;
	size_t len;
	PGPPipeline *tail;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	tail = ctx->tail;
	pgpAssert (tail);
	pgpAssert (error);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;
	/* empty out the buffered data and then the packet */
	for (;;) {
		p = inputRawPeek(&ctx->input, buf, size, &len);
		if (!len)
			break;
		len = tail->write (tail, p, len, error);
		len = inputRawSeek (&ctx->input, buf, size, len);
		buf += len;
		size -= len;
		if (*error)
			return size0-size;
	}

	/* If that's the end of this packet, continue with the next. */
	if (inputFinished (&ctx->input.head)) {
		/* End of input */
		myself->write = nextScope;
		size -= nextScope (myself, buf, size, error);
	}

	return size0-size;
}

/*
 * Tear down the pipeline connected to our tail for the processing of the
 * current packet.  This is the pipeline starting with ctx->tail and
 * ending at *ctx->end.  Note that myself may be zero length, i.e.
 * ctx->end == &ctx->tail!
 */
static void
parsePipelineTeardown (PrsBinContext *ctx)
{
	PGPPipeline *temp;

	pgpAssert (ctx->end);

	/* 
	 * End the pipeline I created, tear it down, and re-attach the
	 * original pipeline
	 */
	temp = *(ctx->end);
	*(ctx->end) = NULL;

	/*
	 * Make sure this isn't a zero-length pipeline, since ctx->end
	 * can point to the address of ctx->tail!
	 */	   
	if (ctx->tail)
		ctx->tail->teardown (ctx->tail);
	ctx->tail = temp;
	ctx->end = NULL;
}

/*
 * Given a candidate encryption key, verify it against the IV that we have
 * stored in the buffer.  If it checks, return the PGPCFBContext
 * set up to decrypt the rest of the packet.  Otherwise, return NULL.
 */
static PGPCFBContext *
CheckKey (
	PGPContextRef	cdkContext,
	PrsBinContext	*ctx,
	PGPByte const	*string,
	size_t			size,
	PGPError		*error
	//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
	//,
	//PGPBoolean		*bIsMDC
	//END MDC PACKET SUPPORT
	)
{
	PGPByte buf[MAXIVLEN+2];
	PGPCFBContext *cfb;
	PGPCipherVTBL const *cipher;
	PGPSize ivlen;
	//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
	unsigned char offset;
	//END MDC PACKET SUPPORT
	unsigned char const *p;
	size_t len;

	if (!size) {
		*error = kPGPError_BadKeyLength;	/* Um, I guess? */
		return (PGPCFBContext *)0;
	}
	cipher = pgpCipherGetVTBL ( (PGPCipherAlgorithm)string[0]);
	if (!cipher) {
		*error = kPGPError_BadCipherNumber;
		return (PGPCFBContext *)0;
	}
	if (size != cipher->keysize+1) {
		*error = kPGPError_BadKeyLength;
		return (PGPCFBContext *)0;
	}

	cfb = pgpCFBCreate ( PGPGetContextMemoryMgr( cdkContext ), cipher);
	if (!cfb) {
		*error = kPGPError_OutOfMemory;
		return (PGPCFBContext *)0;
	}

	ivlen = pgpCFBGetBlockSize( cfb );
	p = inputPeek(&ctx->input, NULL, 0, &len);
	//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
	//*bIsMDC=FALSE;
	offset=2;
	//if ((ivlen > 8) && (p[0]==1))
    if (ctx->bIsMDC)
    {
		p++;//skip over version byte
		//*bIsMDC=TRUE;
		offset=3;
	}
	//if (len < ivlen+2) {
	if (len < ivlen+offset) {
	//END MDC PACKET SUPPORT
		PGPFreeCFBContext (cfb);
		*error = kPGPError_CantDecrypt;
		return (PGPCFBContext *)0;
	}

	/* Set up with zero IV, decrypt first ivlen+2 bytes */
	PGPInitCFB (cfb, string+1, NULL);
	pgpCFBDecryptInternal (cfb, p, ivlen+2, buf);

	if (buf[ivlen] != buf[ivlen-2] || buf[ivlen+1] != buf[ivlen-1]) {
		PGPFreeCFBContext (cfb);
		*error = kPGPError_CantDecrypt;
		return (PGPCFBContext *)0;
	}

	/* Advance pointer to skip the bytes we've used */
	//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
	//ctx->input.bufptr += ivlen+2;
	ctx->input.bufptr += ivlen+offset;
	//END MDC PACKET SUPPORT
	if (ctx->input.bufptr != ctx->input.bufend)
		ctx->nopurge = TRUE;
//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
//#if 0
	/* Only do sync with small block ciphers */
	//if ((pgpCFBGetBlockSize( cfb ) <= 8)
	//	|| (*bIsMDC==FALSE)) //do sync for non MDC also
	if (ctx->bIsMDC==FALSE) //do sync for non MDC
//#endif
//END MDC PACKET SUPPORT
		PGPCFBSync (cfb);

	*error = kPGPError_NoErr;
	return cfb;
}

/*
 * Process one of the incoming annotations that's expected in response to
 * one of our own annotations.  These can happen either during the
 * ctx->tail->annotate() call, or after that call has returned an error
 * to the top level, which makes the call in turn.  Either way, we have
 * to change state appropraitely.
 *
 * Currently, there are 4 things that can be done with any given packet:
 * - Eat it silently.  No data will be emitted before the end scope
 *   annotation.
 * - Pass it through as ciphertext.
 * - Decode it, and pass the body through as plaintext. The body is *not*
 *   parsed further.
 * - Decode it and parse it recursively.
 *
 * The latter two options depend on the type of packet we're inside, as
 * recorded in the ctx->end_scope variable.  They do some special
 * processing setting up a pipeline to do the decoding, then everyone
 * appends another parser to the chain and sets things up to write the
 * packet body to the decoding pipe.
 */
//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
	CHAR sztmp[60];
//END MDC PACKET SUPPORT
static PGPError
ProcessCallback (PGPPipeline *myself, int type,
                 PGPByte const *string, size_t size)
{
	PrsBinContext *ctx = (PrsBinContext *)myself->priv;
	PGPPipeline *oldhead;
	PGPCFBContext *cfb;
	PGPError	error = kPGPError_NoErr;
	PGPContextRef	cdkContext;
    PGPMemoryMgrRef	memoryMgr	= NULL;
	//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
	//PGPBoolean	bIsMDC = FALSE;
	//CHAR sztmp[60];
	//END MDC PACKET SUPPORT
	
	pgpAssertAddrValid( myself, PGPPipeline );
	cdkContext	= myself->cdkContext;
	memoryMgr	= PGPGetContextMemoryMgr( cdkContext );

	pgpAssert(ctx->needcallback);	/* Maybe a less nasty failure? */

	pgpAssert(!ctx->end);	/* This will change in future, but for now */

	if (!ctx->end)
		ctx->end = &ctx->tail;
	oldhead = *ctx->end;
	*ctx->end = NULL;

	/* The other option is to make this illegal... */
	if (ctx->end_scope == PGPANN_NONPACKET_END &&
            (type == PGPANN_PARSER_PROCESS || type == PGPANN_PARSER_RECURSE))
		type = PGPANN_PARSER_PASSTHROUGH;

	/* Type will ONLY be one of these! */
	switch (type) {
	case PGPANN_PARSER_EATIT:
		myself->write = DoSkip;
		break;
	case PGPANN_PARSER_PASSTHROUGH:
		if (ctx->end_scope == PGPANN_PGPKEY_END) {
			/* Passthrough is unreasonable on keys */
			type = PGPANN_PARSER_PROCESS;
			break;
		}
		ctx->end = pgpHeaderCreate ( myself->cdkContext, ctx->end);
		if (!ctx->end) {
			error = kPGPError_OutOfMemory;
			break;
		}
		myself->write = DoPassthrough;
		break;
	case PGPANN_PARSER_PROCESS:
	case PGPANN_PARSER_RECURSE:
		switch (ctx->end_scope) {
		case PGPANN_LITERAL_END:
			if (type == PGPANN_PARSER_PROCESS &&
				ctx->subtype == PGP_LITERAL_RECURSE) {
				/* Decided not to recurse, fixup subtype and type */
				type = PGPANN_PARSER_RECURSE;
				ctx->subtype = PGP_LITERAL_TEXT;
				error = oldhead->annotate (oldhead, myself,
		                              PGPANN_LITERAL_TYPE, &ctx->subtype, 1);
			}
			if (type == PGPANN_PARSER_RECURSE &&
			    ctx->subtype == PGP_LITERAL_TEXT) {
				PGPByte const *charmap;
				PGPLineEndType lineEnd = pgpGetDefaultLineEndType();
				charmap = (PGPByte const *)
					pgpenvGetPointer
					(ctx->env, PGPENV_CHARMAPTOLOCAL, NULL);
				/* Recurse means filter the text */
				ctx->end = pgpTextFiltCreate ( myself->cdkContext,
							ctx->end,  charmap,  0, lineEnd );
				if (!ctx->end) {
					error = kPGPError_OutOfMemory;
					break;
				}
			} else if (type == PGPANN_PARSER_RECURSE &&
					   ctx->subtype == PGP_LITERAL_RECURSE) {
				/* Want to recurse inside literal packet */
				PGPPipeline **temp = ctx->end;
				PGPBoolean trueflag = TRUE;

				ctx->end = pgpParseAscCreate ( myself->cdkContext,
							ctx->end, ctx->env, &pgpByteFifoDesc,
							ctx->ui, ctx->ui_arg );
				ctx->nextparser = *temp;
				if (!ctx->end) {
					error = kPGPError_OutOfMemory;
					break;
				}
				/* Chain end of pipeline so can do annotation */
				*(ctx->end) = oldhead;
				ctx->needcallback--;
				/* Set ascii armor to passthroughclearsign mode */
				ctx->nextparser->annotate( ctx->nextparser, NULL,
										   PGPANN_PASSTHROUGH_CLEARSIGN,
										   &trueflag, 1 );
				if (!ctx->nopurge)
					inputPurge(&ctx->input);
				ctx->nopurge = FALSE;
				myself->write = DoWrite;
				return error;
			}
			type = PGPANN_PARSER_PROCESS;
			break;
		case PGPANN_CIPHER_END:
			//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
			cfb = CheckKey (myself->cdkContext, ctx, string, size, &error);
			//cfb = CheckKey (myself->cdkContext, ctx, string, size, &error, &bIsMDC);
			//END MDC PACKET SUPPORT
			if (!cfb)
				break;
			//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
			//if (bIsMDC == TRUE)
			if (ctx->bIsMDC == TRUE)
            {
				//sprintf(sztmp,"pktlen=%i",(int) ctx->input.head.pktlen); 
				//MessageBox(NULL,sztmp,sztmp,MB_OK);
				//discard MDC packet & it's header (2 (Header 0xd0 0x14) + 20(Hash) = 22) 
				ctx->end = pgpCipherModDecryptCreate ( myself->cdkContext,
					ctx->end, cfb, ctx->env, kPGPHashAlgorithm_Invalid, 22);
				//sprintf(sztmp,"pktlen=%i",(int) ctx->input.head.pktlen); 
				//MessageBox(NULL,sztmp,sztmp,MB_OK);
			}
			else
			//END MDC PACKET SUPPORT
				ctx->end = pgpCipherModDecryptCreate ( myself->cdkContext,
					ctx->end, cfb, ctx->env, kPGPHashAlgorithm_Invalid, 0);
			if (!ctx->end)
				error = kPGPError_OutOfMemory;
			break;
		case PGPANN_COMPRESSED_END:
			ctx->end = pgpDecompressModCreate ( cdkContext, ctx->end,
					         *inputMergedPtr(&ctx->input), &error);
			break;
		case PGPANN_COMMENT_END:
		case PGPANN_UNKNOWN_END:
			type = PGPANN_PARSER_PROCESS;
			break;
		case PGPANN_SIGNED_END:
		{
			PGPUInt32	numHashes	=0;
			
			if (ctx->nextparser)
				type = PGPANN_PARSER_PROCESS;
			/* Set up all requested hashes */
			pgpAssert(!ctx->hashes);
			if (!size)
				return kPGPError_NoErr;
			/* Get all the PgpHashContexts */
			error = (PGPError)pgpHashListCreate ( memoryMgr,
				string, &ctx->hashes, size);
			if ( IsPGPError( error ) )
				break;
			numHashes	= pgpHashListGetSize( ctx->hashes );
			/* Make a pipeline out of them */
			ctx->end = pgpHashModListCreate ( cdkContext,
							ctx->end,  ctx->hashes, numHashes);
			if (!ctx->end) {
				pgpHashListDestroy (ctx->hashes );
				ctx->hashes = NULL;
				error = kPGPError_OutOfMemory;
				break;
			}
			pgpAssert(inputFinished(&ctx->input.head));
			ctx->input.head.pktlen = (PGPUInt32)-1l; /* Write through rest */
			ctx->input.silent_trunc = 1;
			error = kPGPError_NoErr;
			break;
		}

		case PGPANN_PGPKEY_END:
			type = PGPANN_PARSER_PROCESS;
			break;
		default:
			error = kPGPError_BadParams;
		}

		/*
		 * Processing for all packet types... set up parser if
		 * desired, then skip any header prifix in the buffer,
		 * then arrange to write out what we have.
		 */
		/* If we want to create a parser, do that */
		if (!error && type == PGPANN_PARSER_RECURSE) {
			PGPPipeline **temp = ctx->end;

			ctx->end = pgpParseBinCreate ( myself->cdkContext,
						ctx->end, ctx->env, ctx->ui, ctx->ui_arg);
			if (!ctx->end)
				error = kPGPError_OutOfMemory;
			ctx->nextparser = *temp;
		}
		if (!error && type == PGPANN_PARSER_PROCESS) {
			/* Add a header if appropriate */
			switch (ctx->end_scope) {
			case PGPANN_CIPHER_END:
			case PGPANN_COMPRESSED_END:
			case PGPANN_SIGNED_END:
				ctx->end = pgpHeaderCreate ( myself->cdkContext, ctx->end);
				if (!ctx->end)
					error = kPGPError_OutOfMemory;
			}
		}
		/* Success!  Flush data and write through the rest */
		if (!error) {
			if (ctx->end_scope == PGPANN_SIGNED_END) {
				if (ctx->state >= 10)
					myself->write = DoSignedLiteralMagic;
				else if (ctx->sig1pass)
					myself->write = DoWriteSignedPackets;
				else {
					if( !ctx->nopurge )
						inputPurge( &ctx->input );
					ctx->nopurge = FALSE;
					myself->write = DoWrite;
				}
			} else {
				if (ctx->end_scope == PGPANN_PGPKEY_END)
					myself->write = parseKey;
				else {
					if( !ctx->nopurge )
						inputPurge( &ctx->input );
					ctx->nopurge = FALSE;
					myself->write = DoWrite;
				}
			}
			break;
		}
		break;
	default:
		error = kPGPError_BadParams;
	}

	if (error) {
		/* Get rid of partial pipelines (if any) */
		if (IsNull(ctx->end)  ||  IsNull(*(ctx->end)))
			ctx->end = &oldhead;
		parsePipelineTeardown (ctx);
	} else {
		/* Splice the new into the old */
		*(ctx->end) = oldhead;
		ctx->needcallback--;
	}

	return error;
}

static size_t
parseLiteral (PGPPipeline *myself, PGPByte const *buf, size_t size,
		PGPError *error)
{
	PrsBinContext *ctx;
	size_t len;
	size_t size0 = size;
	PGPByte const *p;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
	case 10:	/* flags oldliteral, where length doesn't include prefix */
				/* may also be pgpHeader.c packet, type 'P' */
		/* Parse header; needed before callbacks are allowed */
		len = inputMerge(&ctx->input, buf, size, 2, error);
		buf += len;
		size -= len;
		if (*error || !size)
			break;
		/* Size is non-zero but we haven't got desired?  EOP */
		if (inputMerged(&ctx->input) < 2) {
			pgpAssert(inputFinished(&ctx->input.head));
			*error = ctx->tail->annotate(ctx->tail, myself,
			                             PGPANN_PACKET_SHORT,
						     0, 0);
			if (*error)
				break;
			myself->write = nextScope;
			size -= nextScope (myself, buf, size, error);
			break;
		}
		p = inputMergedPtr(&ctx->input);
		/* Deal with "oldliteral" packets specially */
		if (ctx->state == 10) {
			if (p[0] == 'P') {
				/* Special PGP 3 header */
				myself->write = DoSkip;
				size -= DoSkip (myself, buf, size, error);
				break;
			}
			/* Else old-style packets; some PGPcompatible program does these */
			/*
			 * That program uses "literal" length conventions, not
			 * "oldliteral", so don't do this:
			 *
			 * if (ctx->input.head.pktlen != ~0UL) {
			 *   ctx->input.head.pktlen += 6 + p[1];
			 * }
			 */
			ctx->state = 0;
		}
		/* Get the name and timestamp fields */
		len = inputMerge(&ctx->input, buf, size, 6+p[1], error);
		buf += len;
		size -= len;
		/* Size may be zero here if output file is zero length */
		if (*error)
			break;
		if (inputMerged(&ctx->input) < (unsigned)6+p[1]) {
			if( size == 0 )
				break;
			/* Size is non-zero but we haven't got desired?  EOP */
			pgpAssert(inputFinished(&ctx->input.head));
			*error = ctx->tail->annotate(ctx->tail, myself,
			                             PGPANN_PACKET_SHORT,
						     0, 0);
			if (*error)
				break;
			myself->write = nextScope;
			size -= nextScope (myself, buf, size, error);
			break;
		}

		ctx->subtype = p[0];
		ctx->needcallback = 1;
		ctx->end_scope = PGPANN_LITERAL_END;
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_LITERAL_BEGIN, 0, 0);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		p = inputMergedPtr(&ctx->input);
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_LITERAL_NAME,
		                              p+2, (size_t)p[1]);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 2:
		/* Parse 4-byte timestamp */
		p = inputMergedPtr(&ctx->input);
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_LITERAL_TIMESTAMP,
		                              p+2+p[1], 4);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 3:
		p = inputMergedPtr(&ctx->input);
		if (ctx->subtype == PGP_LITERAL_TEXT) {
			/* See if looks like PGP message, set as RECURSE type */
			len = inputMerge(&ctx->input, buf, size,
							 6+p[1]+sizeof(pgp_message_begin)-1, error);
			buf += len;
			size -= len;
			if (*error)
				break;
			if (inputMerged(&ctx->input) < 6+p[1]+sizeof(pgp_message_begin)-1){
				/* Get more data if not enough to check */
				if (!inputFinished(&ctx->input.head))
					break;
			} else {
				if (memcmp (p+p[1]+6, pgp_message_begin,
							sizeof(pgp_message_begin)-1) == 0) {
					/* Looks like PGP message, set type as RECURSE */
					ctx->subtype = PGP_LITERAL_RECURSE;
				}
			}
			/* Advance buffer past initial data */
			ctx->input.bufptr += p[1]+6;
			ctx->nopurge = TRUE;
		}
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_LITERAL_TYPE, &ctx->subtype, 1);
		if (*error)
			break;
		
		ctx->state++;
		/* FALLTHROUGH */
	case 4:
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 5:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_PROCESS,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* Zero length files don't produce output, do an extra write here */
		if( myself->write == DoWrite ) {
			ctx->tail->write( ctx->tail, buf, 0, error );
		}
		if (*error)
			break;
		/* Write remaining chars from buf */
		size -= myself->write(myself, buf, size, error);
		break;
	default:
		pgpAssert (0);	/* I should never get here */
	}

	return size0-size;
}

static size_t
parseCipher (PGPPipeline *myself, PGPByte const *buf, size_t size,
	     PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
		/* Parse header; needed before callbacks are allowed */
		//BEGIN MDC PACKET SUPPORT - Disastry
		//written = inputMerge(&ctx->input, buf, size, MAXIVLEN+2, error);
		written = inputMerge(&ctx->input, buf, size,
			(unsigned) (MAXIVLEN + (ctx->bIsMDC ? 3 : 2) ), error);
		//END MDC PACKET SUPPORT
		buf += written;
		size -= written;
		if (*error || !size)
			break;
		/* Size is non-zero but we haven't got desired?  EOP */
		//BEGIN MDC PACKET SUPPORT - Disastry
		//if (inputMerged(&ctx->input) < MAXIVLEN+)
		if (inputMerged(&ctx->input) < (unsigned)(MAXIVLEN + (ctx->bIsMDC ? 3 : 2)) )
		//END MDC PACKET SUPPORT
		{
			pgpAssert(inputFinished(&ctx->input.head));
			*error = ctx->tail->annotate(ctx->tail, myself,
			                             PGPANN_PACKET_SHORT,
						     0, 0);
			if (*error)
				break;
			myself->write = nextScope;
			size -= nextScope (myself, buf, size, error);
			break;
		}

		ctx->needcallback = 1;

		/*
		 * If we're already in an encrypted scope (we've already
		 * sent some ESKs to the user), don't bother sending another
		 * one.
		 */
		if (ctx->end_scope) {	/* Scope alreay open? */
			ctx->state = 2;
			goto got_esk;
		}
		/* No ESKs seen yet - open the scope */
		ctx->end_scope = PGPANN_CIPHER_END;
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_CIPHER_BEGIN, 0, 0);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		/* No ESKs seen yet - dummy one up */
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_SKCIPHER_ESK, 0, 0);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 2:
	got_esk:
		/* Okay, do a commit */
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 3:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_PASSTHROUGH,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		written += myself->write(myself, buf, size, error);
		break;
	default:
		pgpAssert (0);
	}

	return written;
}
#if 0
//BEGIN MDC PACKETS SUPPORT - Imad R. Faiad
static size_t
parseCipherMDC (PGPPipeline *myself, PGPByte const *buf, size_t size,
	     PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;


	switch (ctx->state) {
	case 0:
		/* Parse header; needed before callbacks are allowed */
		written = inputMerge(&ctx->input, buf, size, MAXIVLEN+3, error);
		buf += written;
		size -= written;
		if (*error || !size)
			break;
		/* Size is non-zero but we haven't got desired?  EOP */
		if (inputMerged(&ctx->input) < MAXIVLEN+3) {
			pgpAssert(inputFinished(&ctx->input.head));
			*error = ctx->tail->annotate(ctx->tail, myself,
			                             PGPANN_PACKET_SHORT,
						     0, 0);
			if (*error)
				break;
			myself->write = nextScope;
			size -= nextScope (myself, buf, size, error);
			break;
		}

		ctx->needcallback = 1;

		/*
		 * If we're already in an encrypted scope (we've already
		 * sent some ESKs to the user), don't bother sending another
		 * one.
		 */
		if (ctx->end_scope) {	/* Scope alreay open? */
			ctx->state = 2;
			goto got_esk;
		}
		/* No ESKs seen yet - open the scope */
		ctx->end_scope = PGPANN_CIPHER_END;
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_CIPHER_BEGIN, 0, 0);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		/* No ESKs seen yet - dummy one up */
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_SKCIPHER_ESK, 0, 0);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 2:
	got_esk:
		/* Okay, do a commit */
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 3:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_PASSTHROUGH,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		written += myself->write(myself, buf, size, error);
		break;
	default:
		pgpAssert (0);
	}

	return written;
}
//END MDC PACKETS SUPPORT
#endif
static size_t
parseCompressed (PGPPipeline *myself, PGPByte const *buf, size_t size,
		 PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
		/* Make sure we have the compression type */
		written = inputMerge(&ctx->input, buf, size, 1, error);
		buf += written;
		size -= written;
		if (*error || !size)
			break;
		/* Size is non-zero but we haven't got desired?  EOP */
		if (inputMerged(&ctx->input) < 1) {
			pgpAssert(inputFinished(&ctx->input.head));
			*error = ctx->tail->annotate(ctx->tail, myself,
			                             PGPANN_PACKET_SHORT,
						     0, 0);
			if (*error)
				break;
			myself->write = nextScope;
			size -= nextScope (myself, buf, size, error);
			break;
		}

		ctx->needcallback = 1;
		ctx->end_scope = PGPANN_COMPRESSED_END;
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_COMPRESSED_BEGIN,
		                              inputMergedPtr(&ctx->input), 1);
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 2:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_RECURSE,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		written += myself->write(myself, buf, size, error);
		break;
	default:
		pgpAssert (0);
	}

	return written;
}

/*
 * Parse a general headerless packet.  Unknown packets, comment packets
 * and, in fact, things that aren't packets at all!
 */
static size_t
parseUnknown (PGPPipeline *myself, PGPByte const *buf, size_t size,
	PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;
	PGPByte b;
	int begintype;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
		/*
		 * As a convenience, we merge a leading prefix of the packet
		 * for identification purposes.
		 */
		written = inputMerge(&ctx->input, buf, size, 256, error);
		buf += written;
		size -= written;
		if (*error)
			return written;
		if (inputMerged(&ctx->input) < 256 &&
		    !inputFinished(&ctx->input.head))
		{
			pgpAssert(!size);
			return written;
		}

		/*
		 * We use this one function to provide different
		 * annotations for non-packets, comment packets, and
		 * unknown packets.  Figure out the right one to use.
		 */
		b = ctx->input.buffer[0];
		if (!IS_OLD_PKTBYTE(b) && !IS_NEW_PKTBYTE(b)) {
			begintype = PGPANN_NONPACKET_BEGIN;
			ctx->end_scope = PGPANN_NONPACKET_END;
		} else if (PKTBYTE_TYPE (b) == PKTBYTE_COMMENT) {
			begintype = PGPANN_COMMENT_BEGIN;
			ctx->end_scope = PGPANN_COMMENT_END;
		} else {
			begintype = PGPANN_UNKNOWN_BEGIN;
			ctx->end_scope = PGPANN_UNKNOWN_END;
		}
		
		ctx->needcallback = 1;
		*error = ctx->tail->annotate (ctx->tail, myself, begintype,
		                              inputMergedPtr(&ctx->input),
		                              inputMerged(&ctx->input));
		if (*error)
			break;

		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 2:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself, PGPANN_PARSER_EATIT,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		return written + myself->write(myself, buf, size, error);
		/* NOTREACHED */
	default:
		pgpAssert (0);
	}

	return written;
}

/*
 * This is called for most all key-type packets.  Keys are just output
 * within a key annotation scope.  There is no callback, since no
 * processing is done.
 */
static size_t
parseKey (PGPPipeline *myself, PGPByte const *buf, size_t size, PGPError *error)
{
	PrsBinContext *ctx;
	PGPPipeline *tail;
	size_t size0 = size;
	PGPByte const *p;
	size_t len;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);

	tail = ctx->tail;
	pgpAssert (tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;
	if (ctx->end_scope && ctx->end_scope != PGPANN_PGPKEY_END) {
		/* Umm.. Key block within another scope??? Why??? */
		*error = kPGPError_WrongScope;
		return 0;
	}

	/* If we haven't output the begin annotation, do so now. */
	if (!ctx->end_scope) {
		*error = tail->annotate (tail, myself, PGPANN_PGPKEY_BEGIN,
					 NULL, 0);
		if (*error)
			return 0;

		ctx->end_scope = PGPANN_PGPKEY_END;

		/* Set the flag to add a header module */
		ctx->needcallback++;
	}

	/* Make sure we only send the annotations once! */
	switch (ctx->state) {
	case 0:
		/*
		 * Ask the user what to do with these keys...  Really,
		 * the only real answers are "EatIt" or "Process"..
		 * "Recurse" gets mapped to "Process", and
		 * "PassThrough" has the same effect.  But let the
		 * user decide, anyways.  They may wish to eatit.
		 */
		if (ctx->needcallback) {
			*error = tail->annotate (tail, myself, PGPANN_COMMIT,
						 0, 0);
			if (*error)
				return 0;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_PROCESS,
						  NULL, 0);
			if (*error)
				return 0;
		}
	}

	/* output this packet */
	/* empty out the buffered data and then the packet */
	for (;;) {
		p = inputRawPeek(&ctx->input, buf, size, &len);
		if (!len)
			break;
		len = tail->write (tail, p, len, error);
		len = inputRawSeek (&ctx->input, buf, size, len);
		buf += len;
		size -= len;
		if (*error)
			return size0-size;
	}
	/*
	 * If we've hit the end of the packet, check if we have
	 * another one.  If so, check if it is a key certificate
	 * packet.  If so, go parse the new packet.  Otherwise, end
	 * this scope.
	 * NOTE: This is not robust against the addition of new kinds of
	 * key packets.  We should instead assume that we are still in the
	 * keyring until we hit a known non-key packet, or we get an
	 * annotation from the ascii armor parser that we are no longer
	 * in the same input block.
	 */
	if (inputFinished (&ctx->input.head) && (size || ctx->eof)) {
		/* End of input */
		if (size)
			switch (PKTBYTE_TYPE (*buf)) {
			case PKTBYTE_SECKEY:
			case PKTBYTE_PUBKEY:
			case PKTBYTE_SECSUBKEY:
			case PKTBYTE_PUBSUBKEY:
			case PKTBYTE_TRUST:
			case PKTBYTE_NAME:
			case PKTBYTE_ATTRIBUTE:
			case PKTBYTE_SIG:
			case PKTBYTE_COMMENT:
			case PKTBYTE_CRL:
			//BEGIN GPG NEW PACKET COMMENT (#61) SUPPORT - Imad R. Faiad
			case PKTBYTE_NEWCOMMENT:
			//END GPG NEW PACKET COMMENT (#61) SUPPORT
				ctx->findpkt = 1;
				myself->write = parsePacket;
				size -= parsePacket (myself, buf, size, error);
				break;
			default:
				myself->write = nextScope;
				size -= nextScope (myself, buf, size, error);
				break;
			}
		else {
			myself->write = nextScope;
			size -= nextScope (myself, buf, size, error);
		}
	}

	return size0-size;
}

/* Shared entry point for 1-pass and old-style sig header parsing */
static size_t
parseSignature (PGPPipeline *myself, PGPByte const *buf, size_t size,
		PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	switch (ctx->state) {
	case 0:
		/* Suck in the whole packet */

		written = inputMerge(&ctx->input, buf, size, (unsigned)-1, error);
		buf += written;
		size -= written;

		/*
		 * Proceed with our key signature test if finished or overfull;
		 * we can handle oversized sigs in keyrings as we're just passing
		 * them through.
		 */
		if ( !( inputFinished(&ctx->input.head) ||
				inputOverfull(&ctx->input) ) )
			return written;

		/* We need at least one byte of look-ahead for next test */
		if (!size && !ctx->eof)
			return written;

		/* Check if this is a key signature */
		{
			int type;

			type = pgpSigSigType (inputMergedPtr (&ctx->input),
					      inputMerged(&ctx->input));
			if (type < 0) {
				*error = (PGPError)type;
				return written;
			}

			if (type & 0xF0) {
				/* This is a key signature */
				myself->write = parseKey;
				return written + parseKey (myself, buf, size,
							   error);
			}

			/* A buggy keyring could have a non-key signature in it.
			 * We recognize that by being in a PGPKEY scope and having
			 * the next packet not being a literal.  This could eliminate
			 * some extremely rare cases where a key block was followed by
			 * a signature on a non-literal, but sigs on non-literals are
			 * themselves rare.
			 */
			if (ctx->end_scope == PGPANN_PGPKEY_END &&
				!ctx->eof &&
				PKTBYTE_TYPE(*buf) != PKTBYTE_LITERAL &&
				PKTBYTE_TYPE(*buf) != PKTBYTE_OLDLITERAL) {
				/* Treat as a key signature */
				myself->write = parseKey;
				return written + parseKey (myself, buf, size,
							   error);
			}
		}

		/* Report a packet larger than the buffer */
		if (inputOverfull(&ctx->input)) {
			*error = ctx->tail->annotate (ctx->tail, myself,
						      PGPANN_SIGNATURE_TOO_BIG,
						   inputMergedPtr(&ctx->input),
						   inputMerged(&ctx->input));
			if (*error)
				return written;

			/* Skip the body of the packet */
			myself->write = DoSkip;
			return written + DoSkip(myself, buf, size, error);
		}

		/* Have we sucked in the whole packet? */
		if (!inputFinished(&ctx->input.head))
			return written;

		/*
		 * We can get here if there is a normal signed message
		 * just after a key packet.  In this case we need to
		 * end the PGPKEY scope and then start a new one.
		 */
		if (ctx->end_scope == PGPANN_PGPKEY_END) {
			/* we need to end the PGPKEY scope.  Yikes! */
			*error = ctx->tail->annotate (ctx->tail, myself,
						      ctx->end_scope, NULL, 0);
			if (*error)
				return 0;

			ctx->end_scope = 0;
		}

		if (ctx->eof ||
		    (!IS_OLD_PKTBYTE(*buf) && !IS_NEW_PKTBYTE(*buf)))
		{
			/* Do separate signature thing */
			ctx->state = 20;
			goto sepsig;
		}

		if (PKTBYTE_TYPE(*buf) == PKTBYTE_LITERAL ||
			PKTBYTE_TYPE(*buf) == PKTBYTE_OLDLITERAL) {
			/* Do signature on literal */
			ctx->state = 10;
			goto sigliteral;
		}

		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		/* It's a signed PGP file (not a literal) */
		ctx->needcallback = 1;
		/* Send only one BEGIN annotation */
		if (ctx->end_scope != PGPANN_SIGNED_END) {
			ctx->end_scope = PGPANN_SIGNED_END;
			*error = ctx->tail->annotate (ctx->tail, myself,
						      PGPANN_SIGNED_BEGIN,0,0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 2:
		/* Dump the signature as an annotation */
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_SIGNED_SIG,
		                              inputMergedPtr(&ctx->input),
		                              inputMerged(&ctx->input));
		if (*error)
			break;
		ctx->state++;
		/* FALLTHROUGH */
	case 3:
		if (ctx->sig1pass) {
			if (!pgpSigNestFlag(inputMergedPtr(&ctx->input),
					 inputMerged(&ctx->input))) {
				/* No nest flag means another sighdr follows */
				myself->write = nextScope;
				break;	/* Call nextScope next time */
			} else if (IS_NEW_PKTBYTE(*buf) &&
				   PKTBYTE_TYPE(*buf)==PKTBYTE_SIG) {
				/*
				 * A 1-pass header immediately followed by
				 * a 1-pass footer can only mean one thing:
				 * a separate signature.  With these, the
				 * reader will try to check sigs as soon as
				 * we ask it to commit.  So we can't do that
				 * until we have read our footer signatures.
				 */
				ctx->sepsig = 1;
				*error = ctx->tail->annotate (ctx->tail,
						      myself,
						      PGPANN_SIGNED_SEP, 0, 0);

				/* Process end of message sigs */
				myself->write = nextScope;
				break; /* Call nextScope next time */
			}
		}


		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 4:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_RECURSE,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state = 0;
		written += myself->write(myself, buf, size, error);
		break;

	/* Signature on literal case */
	case 10:
sigliteral:
		ctx->needcallback = 1;
		/* Send only one BEGIN annotation */
		if (ctx->end_scope != PGPANN_SIGNED_END) {
			ctx->end_scope = PGPANN_SIGNED_END;
			*error = ctx->tail->annotate (ctx->tail, myself,
						      PGPANN_SIGNED_BEGIN,0,0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 11:
		/* Dump the signature as an annotation */
		*error = ctx->tail->annotate (ctx->tail, myself,
					      PGPANN_SIGNED_SIG,
		                              inputMergedPtr(&ctx->input),
		                              inputMerged(&ctx->input));
		if (*error)
			break;
		ctx->state++;
		/* FALLTHROUGH */
	case 12:
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 13:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself,
						  PGPANN_PARSER_RECURSE,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state = 0;
		written += myself->write(myself, buf, size, error);
		break;

	/* Separate signature case */
	case 20:
sepsig:
		ctx->needcallback = 1;
		/* Send only one BEGIN annotation */
		if (ctx->end_scope != PGPANN_SIGNED_END) {
			ctx->end_scope = PGPANN_SIGNED_END;
			*error = ctx->tail->annotate (ctx->tail, myself,
						      PGPANN_SIGNED_BEGIN,0,0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 21:
		/*
		 * Say that this will be a separate signature.
		 * Note that we don't set the sepsig flag here, as we don't
		 * need to know.  That flag is just for 1-pass signatures.
		 */
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_SIGNED_SEP, 0, 0);
		if (*error)
			break;
		ctx->state++;
		/* FALLTHROUGH */
	case 22:
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_SIGNED_SIG,
		                              inputMergedPtr(&ctx->input),
		                              inputMerged(&ctx->input));
		if (*error)
			break;
		ctx->state++;
		/* FALLTHROUGH */
	case 23:
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 24:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself, PGPANN_PARSER_EATIT,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state = 0;
		written += myself->write(myself, buf, size, error);
		break;

	default:
		pgpAssert (0);
	}

	return written;
}


/*
 * Parse 2nd signature packet after the signed packet after a
 * 1-pass signature packet.  These are the "sig footer" packets
 * which are full-sized signature packets, paired with the 1-pass
 * sig header packets.
 */
static size_t
parseSignature1Pass2 (PGPPipeline *myself, PGPByte const *buf,
		size_t size, PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	switch (ctx->state) {
	case 0:
		/* Suck in the whole signature packet */

		written = inputMerge(&ctx->input, buf, size, (unsigned)-1, error);
		buf += written;
		size -= written;

		/* Handle a packet larger than the buffer somehow */
		if (inputOverfull(&ctx->input)) {
			*error = ctx->tail->annotate (ctx->tail, myself,
						      PGPANN_SIGNATURE_TOO_BIG,
						   inputMergedPtr(&ctx->input),
						   inputMerged(&ctx->input));
			if (*error)
				return written;

			/* Skip the body of the packet */
			myself->write = DoSkip;
			return written + DoSkip(myself, buf, size, error);
		}

		/* Have we sucked in the whole packet? */
		if (!inputFinished(&ctx->input.head))
			return written;
		/* FALLTHROUGH */
	case 1:
		/* Dump the signature data as an annotation */
		ctx->needcallback = 1;
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_SIGNED_SIG2,
					      inputMergedPtr(&ctx->input),
					      inputMerged(&ctx->input));
		if (*error)
			break;

		/* Decrement count of sig footers needing to be seen */
		--ctx->sig1pass;

		if (!ctx->sepsig || ctx->sig1pass != 0) {
			/*
			 * In normal case, we are done now.
			 * nextScope will end sig scope if sig1pass is 0.
			 */
			myself->write = nextScope;
			written += nextScope(myself, buf, size, error);
			break;
		}

		/* Here on last sig footer of separate signature */
		ctx->state++;
		ctx->needcallback = 1;
		/* FALLTHROUGH */
	case 2:
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 3:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself, PGPANN_PARSER_EATIT,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state = 0;
		written += myself->write(myself, buf, size, error);
		break;
	}

	return written;
}

static size_t
parseESK (PGPPipeline *myself, PGPByte const *buf, size_t size, PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;
	PGPByte b;


	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	b = PKTBYTE_TYPE (ctx->input.buffer[0]);
	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
		/* It's a public-key-encrypted PGP file */
		if (!ctx->end_scope) {
			ctx->end_scope = PGPANN_CIPHER_END;
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_CIPHER_BEGIN,
			                              0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 1:
		written = inputMerge(&ctx->input, buf, size, (unsigned)-1, error);
		buf += written;
		size -= written;

		/* Handle a packet larger than the buffer somehow */
		if (inputOverfull(&ctx->input)) {
			*error = ctx->tail->annotate (ctx->tail, myself,
						      PGPANN_ESK_TOO_BIG,
						   inputMergedPtr(&ctx->input),
						   inputMerged(&ctx->input));
			if (*error)
				return written;

			/* Skip the body of the packet */
			myself->write = DoSkip;
			return written + DoSkip(myself, buf, size, error);
		}

		/* Have we sucked in the whole packet? */
		if (!inputFinished(&ctx->input.head))
			return written;

		ctx->state++;
		/* FALLTHROUGH */
	case 2:
		/* Dump the ESK as an annotation */
		*error = ctx->tail->annotate (ctx->tail, myself,
					      (b == PKTBYTE_ESK ?
					       PGPANN_PKCIPHER_ESK :
					       (b == PKTBYTE_CONVESK ?
						PGPANN_SKCIPHER_ESK :
						-1)), /* XXX */
		                              inputMergedPtr(&ctx->input),
		                              inputMerged(&ctx->input));
		if (*error)
			break;

		ctx->state++;	/* This really isn't needed */
		myself->write = nextESK;
		return written + nextESK(myself, buf, size, error);
		/* NOTREACHED */
	default:
		pgpAssert (0);
	}

	return written;
}

/*
 * This just sends appropriate messages about the lack of text downstream.
 */
static size_t
parseCipherNoText (PGPPipeline *myself, PGPByte const *buf, size_t size,
                   PGPError *error)
{
	PrsBinContext *ctx;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	switch (ctx->state) {
	case 0:
		ctx->needcallback = 1;
		/* Send an annotation */
		*error = ctx->tail->annotate (ctx->tail, myself,
		                              PGPANN_CIPHER_NOTEXT, 0, 0);
		if (*error)
			break;
		ctx->state++;
		/*FALLTHROUGH*/
	case 1:
		/* Send a commit */
		if (ctx->needcallback) {
			*error = ctx->tail->annotate (ctx->tail, myself,
			                              PGPANN_COMMIT, 0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		/* FALLTHROUGH */
	case 2:
		if (ctx->needcallback) {
			*error = ProcessCallback (myself, PGPANN_PARSER_EATIT,
						  0, 0);
			if (*error)
				break;
		}
		ctx->state++;
		return myself->write(myself, buf, size, error);
	default:
		pgpAssert (0);
	} 
	return 0;	/* Never executed; makes compilers happy. */
}

/*
 * The default state when starting to parse a packet.  Once the type and
 * size of the packet has been determined, we don't come back until
 * the end of the packet.  This function *is* called after each packet
 * (by the sizeAdvise(0) handler if necessary), because post-packet
 * cleanup code also resides here.
 *
 * Because the functions in this module rely heavily on tail recursion,
 * if we get called with a large packet (say 16K), it could have literally
 * hundreds of objects on it, and we go hundreds of levels deep on recursion.
 * This exhausts stack space.  Therefore we will limit the amount of data we
 * will accept on one call to PARSER_SIZE_LIMIT.
 */
static size_t
parsePacket (PGPPipeline *myself, PGPByte const *buf, size_t size,
	     PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;
	unsigned b;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);
#if PGP_MACINTOSH
	pgpAssert( StackSpace() >= 4096 );
#endif

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	/* Prevent excessive recursion within this module */
	size = pgpMin(size, PARSER_SIZE_LIMIT);

	/*
	 * findpkt is set to 1 by create and every time we change to
	 * the parsePacket state, and indicates that the first packet
	 * byte has not been found.
	 */
	if (ctx->findpkt) {
		inputReset(&ctx->input);

		if (!size)
			return 0;	/* I need a packet header! */
		ctx->findpkt = 0;
		b = *(buf++);
		size--;
		
		if (inputStart(&ctx->input, (PGPByte)b) < 0) {
			ctx->state = 0;	/* Need to set this */
					/* before jumping ahead */
			myself->write = parseUnknown;
			return 1+parseUnknown (myself, buf, size, error);
		}
		
		written = 1;
	}

	/*
	 * Okay, now we have a packet, with the parser state set up
	 * and the header byte in ctx->input.buffer[0].
	 *
	 * The packet-specific parsers use a state variable, and
	 * expect it to be set to 0 when they begin.
	 */
	ctx->state = 0;

	b = PKTBYTE_TYPE (ctx->input.buffer[0]);

	if (ctx->end_scope == PGPANN_CIPHER_END) {
		switch (b) {
		case PKTBYTE_CONVENTIONAL:
			myself->write = parseCipher;
		//BEGIN MDC PACKET SUPPORT - Disastry
			ctx->bIsMDC = FALSE;
		//END MDC PACKET SUPPORT
			break;
		//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
		case PKTBYTE_ENCRYPTEDMDC:
			myself->write = parseCipher;
			ctx->bIsMDC = TRUE;
			break;
		//END MDC PACKET SUPPORT
		case PKTBYTE_CONVESK:
		case PKTBYTE_ESK:
			myself->write = parseESK;
			break;
		//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
		case PKTBYTE_MDC:
			//MessageBox(NULL,"PKTBYTE_MDC Detected1","PKTBYTE_MDC Detected1",MB_OK|MB_TOPMOST);
		//END MDC PACKET SUPPORT

		default:
			myself->write = parseCipherNoText;
			break;
		}
	} else {
		switch (b) {
		case PKTBYTE_CONVENTIONAL:
			myself->write = parseCipher;
		//BEGIN MDC PACKET SUPPORT - Disastry
			ctx->bIsMDC = FALSE;
		//END MDC PACKET SUPPORT
			break;
		//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
		case PKTBYTE_ENCRYPTEDMDC:
			myself->write = parseCipher;
			ctx->bIsMDC = TRUE;
			break;
		//END MDC PACKET SUPPORT
		case PKTBYTE_OLDLITERAL:
			/*
			 * This may be a dummy header we created, or it may be a
			 * mistaken value from a PGP compatible program, or it may
			 * conceivably be an obsolete old-style literal packet from a
			 * pre-release version of PGP 2.0!
			 * Flag special treatment, and distinguish the cases in
			 * parseLiteral.
			 */
			ctx->state = 10;
			/* FALLTHROUGH */
		case PKTBYTE_LITERAL:
			myself->write = parseLiteral;
			break;
		case PKTBYTE_COMPRESSED:
			myself->write = parseCompressed;
			break;
		case PKTBYTE_SIG:
			if (ctx->sig1pass)
				myself->write = parseSignature1Pass2;
			else
				myself->write = parseSignature;
			break;
		case PKTBYTE_1PASSSIG:
			++ctx->sig1pass;
			ctx->sig1nest = 0;
			ctx->sepsig = 0;
			myself->write = parseSignature;
			break;
		case PKTBYTE_CONVESK:
		case PKTBYTE_ESK:
			myself->write = parseESK;
			break;
		case PKTBYTE_SECKEY:
		case PKTBYTE_PUBKEY:
		case PKTBYTE_SECSUBKEY:
		case PKTBYTE_PUBSUBKEY:
		case PKTBYTE_TRUST:
		case PKTBYTE_NAME:
		case PKTBYTE_COMMENT:
		//BEGIN GPG NEW PACKET COMMENT (#61) SUPPORT - Imad R. Faiad
		case PKTBYTE_NEWCOMMENT:
		//END GPG NEW PACKET COMMENT (#61) SUPPORT
		case PKTBYTE_CRL:
			myself->write = parseKey;
			break;
		
		//BEGIN MDC PACKET SUPPORT - Imad R. Faiad
		case PKTBYTE_MDC:
			//MessageBox(NULL,"PKTBYTE_MDC Detected2","PKTBYTE_MDC Detected2",MB_OK|MB_TOPMOST);
		//END MDC PACKET SUPPORT
		default:
			/* If found in keyring, assume still in one */
			if (ctx->end_scope == PGPANN_PGPKEY_END)
				myself->write = parseKey;
			else
				myself->write = parseUnknown;
			break;
		}
	}
	/* continue processing, if we can */
	return written + myself->write (myself, buf, size, error);
}

/*
 * Start a new packet.  This mostly cleans up after old ones, then
 * falls through to parsePacket.
 */
static size_t
nextScope (PGPPipeline *myself, PGPByte const *buf, size_t size,
		PGPError *error)
{
	PrsBinContext *ctx;
	size_t written = 0;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = kPGPError_NoErr;

	/* Get rid of any buffered data */
	inputPurge(&ctx->input);
	ctx->nopurge = FALSE;

	/* Clean up any pipeline set up to process the packet. */
	if (ctx->end) {
		*error = ctx->tail->sizeAdvise (ctx->tail, 0);
		if (*error)
			return written;

		parsePipelineTeardown (ctx);
		ctx->nextparser = NULL;
	}

	/*
	 * Special handling at end of 1 pass sig signed packet.
	 * Retain hashes and end_scope; parsePacket will then handle
	 * the following signature packet.
	 * XXX
	 * Need to recognize error of having another packet type there.
	 */
	if (!ctx->sig1pass) {

		/* Send the end-scope annotation for the last scope, if any. */
		if (ctx->end_scope) {
			*error = ctx->tail->annotate (ctx->tail, myself,
						      ctx->end_scope, 0, 0);
			if (*error)
				return written;

			ctx->end_scope = 0;
			ctx->input.silent_trunc = 0;
		}

		/* Clean up any pending hashes */
		if (ctx->hashes) {
			pgpHashListDestroy ( ctx->hashes );
			ctx->hashes = 0;
		}

	}

	ctx->findpkt = 1;
	myself->write = parsePacket;
	return parsePacket (myself, buf, size, error);
}

/*
 * After an ESK, call this function, which copies the current packet to
 * the byte FIFO, and sets things up for parsePacket again.
 * It doesn't flush the FIFO or end the current scope.
 */
static size_t
nextESK (PGPPipeline *myself, PGPByte const *buf, size_t size, PGPError *error)
{
	PrsBinContext *ctx;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);
	pgpAssert (error);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);
	pgpAssert (!size || !ctx->eof);

	*error = inputToFifo(&ctx->input);
	if (*error)
		return 0;

	ctx->findpkt = 1;
	myself->write = parsePacket;
	return parsePacket (myself, buf, size, error);
}


static PGPError
Flush (PGPPipeline *myself)
{
	PrsBinContext *ctx;
	PGPError	error = kPGPError_NoErr;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);

	/* Do a write to force out any hanging data */
	myself->write (myself, (PGPByte const *)0, (size_t)0, &error);
	return error ? error : ctx->tail->flush (ctx->tail);
}

static PGPError
Annotate (PGPPipeline *myself, PGPPipeline *origin, int type,
	  PGPByte const *string, size_t size)
{
	PrsBinContext *ctx;
	PGPError	error;
	PGPByte const *oldbufptr;
	size_t (*oldwrite)(PGPPipeline *, PGPByte const *, size_t, PGPError *);

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);

	/* Do any expected callbacks */
	if (ctx->needcallback) {
		switch (type) {
		case PGPANN_PARSER_EATIT:
		case PGPANN_PARSER_PASSTHROUGH:
		case PGPANN_PARSER_PROCESS:
		case PGPANN_PARSER_RECURSE:
			return ProcessCallback (myself, type, string, size);
		}
	}

	/*
	 * If this is a hash request callback, and we have the
	 * requested hash being computed, copy it, hash in the
	 * extra bytes, and pass back the resultant hash.
	 */
	if (type == PGPANN_HASH_REQUEST) {
		PGPHashContext const *hc;
		PGPHashContext *temp_hc;

		if (!size || IsNull( ctx->hashes ))
			return kPGPError_BadHashNumber;
		hc = pgpHashListFind(ctx->hashes,
				     pgpHashByNumber( (PGPHashAlgorithm) string[1]));
		if (!hc)
			return kPGPError_BadHashNumber;
		temp_hc = pgpHashCopy (hc);
		if (!temp_hc)
			return kPGPError_OutOfMemory;
		PGPContinueHash (temp_hc, string+2, size-2);
		if (string[0] == PGPVERSION_4) {
			/* New hash format includes an anti-aliasing postscript */
			PGPByte postscript[6];
			postscript[0] = PGPVERSION_4;	/* actually a 4! */
			postscript[1] = 0xff;			/* different from sig type */
			postscript[2] = (PGPByte)((size-2)>>24);
			postscript[3] = (PGPByte)((size-2)>>16);
			postscript[4] = (PGPByte)((size-2)>> 8);
			postscript[5] = (PGPByte)((size-2)>> 0);
			PGPContinueHash (temp_hc, postscript, sizeof(postscript));
		}
		error = ctx->tail->annotate (ctx->tail, origin,
					     PGPANN_HASH_VALUE,
		                             (PGPByte *) pgpHashFinal(temp_hc),
		                             pgpHashGetVTBL( hc )->hashsize);
		PGPFreeHashContext (temp_hc);

		return error;
	}

	/*
	 * Now, ensure that we have written out everything buffered that
	 * we plan on writing out.  Run the state machine forward until
	 * it stops changing.
	 */
	do {
		oldbufptr = ctx->input.bufptr;
		oldwrite = myself->write;
		(void)oldwrite(myself, 0, 0, &error);
		if (error)
			return error;
	} while (ctx->input.bufptr != oldbufptr || myself->write != oldwrite);

	return ctx->tail->annotate (ctx->tail, origin, type, string, size);
}

static PGPError
SizeAdvise (PGPPipeline *myself, unsigned long bytes)
{
	PrsBinContext *ctx;
	PGPError	error;
	PGPByte const *oldbufptr;
	size_t (*oldwrite)(PGPPipeline *, PGPByte const *, size_t, PGPError *);

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);
	pgpAssert (ctx->tail);

	/*
	 * If we're in the middle of a packet that can be truncated
	 * without error, deal with it.
	 */
	if (ctx->input.silent_trunc && ctx->input.head.pktlen > bytes)
		ctx->input.head.pktlen = bytes;
	/*
	 * Set eof flag, which a few of the parsing functions need
	 * to do special things at EOF when the default processing here
	 * is not desired.
	 */
	if (!bytes)
		ctx->eof = 1;
	/*
	 * Now, ensure that we have written out everything buffered that
	 * we plan on writing out.  Run the state machine forward until
	 * it stops changing.
	 */
	do {
		oldbufptr = ctx->input.bufptr;
		oldwrite = myself->write;
		(void)oldwrite(myself, 0, 0, &error);
		if (error)
			return error;
	} while (ctx->input.bufptr != oldbufptr || myself->write != oldwrite);

	/*
	 * Are we shutting down, yet not in a clean-shutdown state?
	 * (No pending packets, no bytes waiting to be parsed.)
	 */
	if (!bytes && !inputFinished(&ctx->input.head)) {
		if (!ctx->input.silent_trunc) {
			error = (PGPError)(ctx->end_scope ? PGPANN_SCOPE_TRUNCATED :
						 PGPANN_PACKET_TRUNCATED);
			error = ctx->tail->annotate (ctx->tail, myself,
			                             error, 0, 0);
			if (error)
				return error;
			ctx->input.silent_trunc = 1;	/* Don't repeat */
		}

		/* Let nextScope do the cleanup. */
		myself->write = nextScope;
		(void)nextScope(myself, 0, 0, &error);
		if (error)
			return error;
	}

	/*
	 * Send down a final annotation...
	 */
	if (!bytes && ctx->end_scope == 0)
		return ctx->tail->sizeAdvise (ctx->tail, 0);
	return kPGPError_NoErr;
}

static PGPError
Teardown (PGPPipeline *myself)
{
	PrsBinContext *ctx;
	PGPContextRef	cdkContext;
	
	pgpAssertAddrValid( myself, PGPPipeline );
	cdkContext	= myself->cdkContext;

	pgpAssert (myself);
	pgpAssert (myself->magic == PARSERMAGIC);

	ctx = (PrsBinContext *)myself->priv;
	pgpAssert (ctx);

	if (ctx->tail)
		ctx->tail->teardown (ctx->tail);

	pgpFifoDestroy (&pgpByteFifoDesc, ctx->input.fifo);
	pgpClearMemory( ctx,  sizeof (*ctx));
	pgpContextMemFree( cdkContext, ctx);
	
	return kPGPError_NoErr;
}

PGPPipeline **
pgpParseBinCreate (
	PGPContextRef cdkContext,
	PGPPipeline **head, PGPEnv const *env,
	PGPUICb const *ui, void *ui_arg )
{
	PGPPipeline *mod;
	PrsBinContext *ctx;

	if (!head || !env)
		return NULL;

	ctx = (PrsBinContext *)pgpContextMemAlloc( cdkContext,
		sizeof (*ctx), kPGPMemoryMgrFlags_Clear);
	if (!ctx)
		return NULL;
	mod = &ctx->pipe;

	ctx->input.fifo = pgpFifoCreate (cdkContext, &pgpByteFifoDesc);
	if (!ctx->input.fifo) {
		pgpContextMemFree( cdkContext, ctx);
		return NULL;
	}
	inputReset(&ctx->input);
	ctx->findpkt = 1;
	ctx->env = env;
	ctx->ui = ui;
	ctx->ui_arg = ui_arg;
	//BEGIN MDC PACKET SUPPORT - Disastry
	ctx->bIsMDC = FALSE;
	//END MDC PACKET SUPPORT

	mod->magic = PARSERMAGIC;
	mod->write = parsePacket;
	mod->flush = Flush;
	mod->sizeAdvise = SizeAdvise;
	mod->annotate = Annotate;
	mod->teardown = Teardown;
	mod->name = "PGP Message Parser";
	mod->priv = ctx;
	mod->cdkContext	= cdkContext;

	ctx->tail = *head;
	*head = mod;
	return &ctx->tail;
}
