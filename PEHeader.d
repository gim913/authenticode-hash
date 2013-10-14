/**
 * PEHeader module provides access for reading in and dealing with PE
 * structures
 *
 * Copyright: Copyright (C) 2008 Michal 'GiM' Spadlinski. All Rights Reserved.
 * License:   GPLv2
 * Authors:   Michal 'GiM' Spadlinski
 *
 * TODO:
 *  + change asserts to exceptions
 *
 */
module PEHeader;

private import tango.io.device.File;
private import tango.io.protocol.Reader;
private import tango.io.protocol.Writer;
private import tango.io.Stdout;
private import tango.text.convert.Layout;
private import tango.stdc.stringz;

debug = doGetCheck;

/**
 * Simple unsigned int to hex-string converting function
 * computables at compile time.
 */
private char[] tohex(uint i)
{
	const char[] digi="0123456789abcdef";
	if (i >= 16)
		return tohex(i>>4)~digi[i&0xf];
	else
		return ""~digi[i];
}

template isArray(T) { const isArray=false; }
template isArray(T: T[]) { const isArray=true; }

/**
 * This template tries to generete at compile time string
 * describing a structure. I don't think it'd handle unions.
 *
 * Examples:
 * ----------
 * struct A { int inA_1; }
 * struct B { char inB_1; A inB_2; }
 * struct C { B inC_1; A inC_2; float inC_3; }
 * pragma (msg, RetriveFields!(C, "foobar", 0));
 * ----------
 * will output the following string:
 * "(foobar.inC_1.inB_1) (foobar.inC_1.inB_2.inA_1)
 *  (foobar.inC_2.inA_1) (foobar.inC_3)"
 *
 * Params:
 *	T =	Structure type name
 *	name =	Desired structure name
 *	u =	Internal use, should be 0 at first call.
 *
 */
template RetriveFields(T, char[] name, int u)
{
	static if (is(T == struct) || is(T == class))
	{
	    static if (u < T.tupleof.length)
	    {
		static if (is(typeof(T.tupleof[u]) == struct)) {
		    const char[] RetriveFields = RetriveFields!(typeof(T.tupleof[u]), 
			    (name~ (T.tupleof[u].stringof[T.stringof.length+2 .. $])), 0) 
			~ RetriveFields!(T, name, u+1);
		} else static if (isArray!(typeof(T.tupleof[u]))) {
		    const char[] RetriveFields = RetriveFields!(typeof(T.tupleof[u]), 
			    (name~ (T.tupleof[u].stringof[T.stringof.length+2 .. $])), 0) 
			~ RetriveFields!(T, name, u+1);
		} else static if (T.tupleof[u].stringof[T.stringof.length+2 .. $] == ".this") {
		    const char[] RetriveFields = RetriveFields!(T, name, u+1);
		} else {
		    const char[] RetriveFields =  "(" ~ name ~ T.tupleof[u].stringof[T.stringof.length+2 .. $] ~ ") " ~ RetriveFields!(T, name, u+1);
		}
	    } else
		const char[] RetriveFields = "";
	} else static if (isArray!(T)) {
	    static if (u < T.length) {
		static if (is(typeof(T[0]) == struct)) {
		    const char[] RetriveFields = RetriveFields!(typeof(T[0]), name~"[0x"~tohex(u)~"]", 0) ~ RetriveFields!(T, name, u+1);
		} else static if (isArray!(T)) {
		    const char[] RetriveFields = RetriveFields!(typeof(T[0]), name~"[0x"~tohex(u)~"]", 0) ~ RetriveFields!(T, name, u+1);
		} else {
		    const char[] RetriveFields = name~"[0x" ~ tohex(u) ~ "]" ~ RetriveFields!(T, name, u+1);
		}
	    } else {
		const char[] RetriveFields = "";
	    }
	} else {
		    const char[] RetriveFields = "(" ~ name ~ ")";
	}
}

class PEException : Exception
{
    this(char[] file, long line = 0) { super("Failure in PE", file, line); }
    char[] toString()
    {
        return msg ? super.toString() : "Failure in PEHeader";
    }
}

class PEHeader
{
    /**
     * Structure representing PE Image File
     * which starts at lfanew offset with 'PE\0\0'
     * signature
     */
    struct ImageFile {/*{{{*/
		uint Magic;			/* 0 */
		ushort Machine;			/* 4 */
		ushort NumberOfSections;	/* 6 */
		uint TimeDateStamp;		/* 8   unreliable */
		uint PointerToSymbolTable;	/* c   debug */
		uint NumberOfSymbols;		/* 10  debug */
		ushort SizeOfOptionalHeader;	/* 14  == 224 */
		ushort Characteristics;		/* 16 */
	
		char[] toString() {
		    Layout!(char) tforma = new Layout!(char)();
		    char ret[];
	
		    ret = tforma (" {,35}: {:x08}\n", "Magic",			Magic);
		    ret ~= tforma (" {,35}: {:x04}\n", "Machine",		Machine);
		    ret ~= tforma (" {,35}: {:x04}\n", "NumberOfSections",	NumberOfSections);
		    ret ~= tforma (" {,35}: {:x08}\n", "TimeDateStamp",		TimeDateStamp);
		    ret ~= tforma (" {,35}: {:x08}\n", "PointerToSymbolTable",  PointerToSymbolTable);
		    ret ~= tforma (" {,35}: {:x08}\n", "NumberOfSymbols",	NumberOfSymbols);
		    ret ~= tforma (" {,35}: {:x04}\n", "SizeOfOptionalHeader",  SizeOfOptionalHeader);
		    ret ~= tforma (" {,35}: {:x04}",   "Characteristics",	Characteristics);
	
		    return ret;
		}
    }/*}}}*/
    struct ImageDataDir {/*{{{*/
		uint VirtualAddress;
		uint Size;
    }/*}}}*/

    template ImageOptionalString(int t)/*{{{*/
    {
		char[] toString() 
		{
		    Layout!(char) tforma = new Layout!(char)();
		    char[] ret;
	
		    ret = tforma ("{,35} {:x}\n", "Magic",                       Magic);
		    ret ~= tforma ("{,35} {:x} {:x}\n", "Major/MinorLinkerVersion", MajorLinkerVersion, MinorLinkerVersion);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfCode",                 SizeOfCode);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfInitializedData",      SizeOfInitializedData);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfUninitializedData",    SizeOfUninitializedData);
		    ret ~= tforma ("{,35} {:x}\n", "AddressOfEntryPoint",        AddressOfEntryPoint);
		    ret ~= tforma ("{,35} {:x}\n", "BaseOfCode",                 BaseOfCode);
		    static if (t)
		    	ret ~= tforma ("{,35} {:x}\n", "BaseOfData",                 BaseOfData);
		    ret ~= tforma ("{,35} {:x}\n", "ImageBase",                  ImageBase);
		    ret ~= tforma ("{,35} {:x}\n", "SectionAlignment",           SectionAlignment);
		    ret ~= tforma ("{,35} {:x}\n", "FileAlignment",              FileAlignment);
		    ret ~= tforma ("{,35} {:x} {:x}\n", "Major/MinorOperatingSystemVersion", MajorOperatingSystemVersion, MinorOperatingSystemVersion);
		    ret ~= tforma ("{,35} {:x} {:x}\n", "Major/MinorImageVersion", MajorImageVersion, MinorImageVersion);
		    ret ~= tforma ("{,35} {:x} {:x}\n", "Major/MinorSubsystemVersion", MajorSubsystemVersion, MinorSubsystemVersion);
		    ret ~= tforma ("{,35} {:x}\n", "Win32VersionValue",          Win32VersionValue);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfImage",                SizeOfImage);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfHeaders",              SizeOfHeaders);
		    ret ~= tforma ("{,35} {:x}\n", "CheckSum",                   CheckSum);
		    ret ~= tforma ("{,35} {:x}\n", "Subsystem",                  Subsystem);
		    ret ~= tforma ("{,35} {:x}\n", "DllCharacteristics",         DllCharacteristics);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfStackReserve",         SizeOfStackReserve);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfStackCommit",          SizeOfStackCommit);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfHeapReserve",          SizeOfHeapReserve);
		    ret ~= tforma ("{,35} {:x}\n", "SizeOfHeapCommit",           SizeOfHeapCommit);
		    ret ~= tforma ("{,35} {:x}\n", "LoaderFlags",                LoaderFlags);
		    ret ~= tforma ("{,35} {:x}\n", "NumberOfRvaAndSizes",        NumberOfRvaAndSizes);
		    /*
		    ret ~= tforma ("{,35} {:x8} {:x8}\n", "blah0",			DataDirectory[0].VirtualAddress, DataDirectory[0].Size);
		    ret ~= tforma ("{,35} {:x8} {:x8}\n", "blah1",			DataDirectory[1].VirtualAddress, DataDirectory[1].Size);
		    */
	
		    return ret;
		}
    }
/*}}}*/
    /**
     * Structure representing PE Optional Header, placed
     * right after PE Image File in PE Executable file
     */
    struct ImageOptional32 { /*{{{*/
		ushort Magic;				/* 18 */
		ubyte  MajorLinkerVersion;              /* 1a unreliable */
		ubyte  MinorLinkerVersion;              /* unreliable */
		uint SizeOfCode;                        /* 1c unreliable */
		uint SizeOfInitializedData;             /* 20 unreliable */
		uint SizeOfUninitializedData;           /* 24 unreliable */
		uint AddressOfEntryPoint;		/* 28 */
		uint BaseOfCode;			/* 2c */
		uint BaseOfData;			/* 30 */
		uint ImageBase;                         /* 34 multiple of 64 KB */
		uint SectionAlignment;                  /* 38 usually 32 or 4096 */
		uint FileAlignment;                     /* 3c usually 32 or 512 */
		ushort MajorOperatingSystemVersion;           /* not used */
		ushort MinorOperatingSystemVersion;           /* not used */
		ushort MajorImageVersion;                     /* unreliable */
		ushort MinorImageVersion;                     /* unreliable */
		ushort MajorSubsystemVersion;
		ushort MinorSubsystemVersion;
		uint Win32VersionValue;                 /* 4c ? */
		uint SizeOfImage;			/* 50 */
		uint SizeOfHeaders;			/* 54 */
		uint CheckSum;                          /* 58 NT drivers only */
		ushort Subsystem;			/* 5c */
		ushort DllCharacteristics;
		uint SizeOfStackReserve;
		uint SizeOfStackCommit;
		uint SizeOfHeapReserve;
		uint SizeOfHeapCommit;
		uint LoaderFlags;                           /* ? */
		uint NumberOfRvaAndSizes;                   /* unreliable */
		ImageDataDir DataDirectory[16];
	
		mixin ImageOptionalString!(1);
    }/*}}}*/
    /**
     * Structure representing PE+ Optional Header, placed
     * right after PE Image File in PE Executable file.
     *
     * PE+ is 64bit version.
     */
    struct ImageOptional64 { /*{{{*/
		ushort Magic;
		ubyte  MajorLinkerVersion;                    /* unreliable */
		ubyte  MinorLinkerVersion;                    /* unreliable */
		uint SizeOfCode;                            /* unreliable */
		uint SizeOfInitializedData;                 /* unreliable */
		uint SizeOfUninitializedData;               /* unreliable */
		uint AddressOfEntryPoint;
		uint BaseOfCode;
		/* */ ulong ImageBase;                             /* multiple of 64 KB */
		uint SectionAlignment;                      /* usually 32 or 4096 */
		uint FileAlignment;                         /* usually 32 or 512 */
		ushort MajorOperatingSystemVersion;           /* not used */
		ushort MinorOperatingSystemVersion;           /* not used */
		ushort MajorImageVersion;                     /* unreliable */
		ushort MinorImageVersion;                     /* unreliable */
		ushort MajorSubsystemVersion;
		ushort MinorSubsystemVersion;
		uint Win32VersionValue;                     /* ? */
		uint SizeOfImage;
		uint SizeOfHeaders;
		uint CheckSum;                              /* NT drivers only */
		ushort Subsystem;
		ushort DllCharacteristics;
		/* */ ulong SizeOfStackReserve;
		/* */ ulong SizeOfStackCommit;
		/* */ ulong SizeOfHeapReserve;
		/* */ ulong SizeOfHeapCommit;
		uint LoaderFlags;                           /* ? */
		uint NumberOfRvaAndSizes;                   /* unreliable */
		ImageDataDir DataDirectory[16];
	
		mixin ImageOptionalString!(0);
    }/*}}}*/

    /**
     * This is simple wrapper for above structures
     * to make use transparent to the user
     */
    struct ImageOptional {/*{{{*/
	union {
	    ImageOptional32 *io32;
	    ImageOptional64 *io64;
	}
	enum PEIO { PEIO32, PEIO64 }
	PEIO peio;

	char[] toString()
	{
	    switch(peio)
	    {
		case PEIO.PEIO32:
		    assert (io32 != null);
		    return io32.toString; /* XXX, (*io32).toString; */
		case PEIO.PEIO64:
		    assert (io64 != null);
		    return io64.toString;
		default:
		    assert (0);
	    }
	}
    }/*}}}*/

    /* round down *//*{{{*/
    template AddressRound(char[] name, char[] elem, char[] alignment)
    {
		const char[] AddressRound = `
		    uint `~name~`() {
			uint ret=`~elem~`;
			if (this.outer.imgopt.io32.`~alignment~`) {
			    ret /= this.outer.imgopt.io32.`~alignment~`;
			    ret *= this.outer.imgopt.io32.`~alignment~`;
			}
			return ret;
		    }`;
    }/*}}}*/

    /* round up *//*{{{*/
    template SizeRound(char[] name, char[] elem, char[] alignment)
    {
	const char[] SizeRound = `
	    uint `~name~`() {
		uint ret=`~elem~`, r2=ret;
		if (this.outer.imgopt.io32.`~alignment~`) {
		    ret /= this.outer.imgopt.io32.`~alignment~`;
		    if (r2 % this.outer.imgopt.io32.`~alignment~`)
			++ret;
		    ret *= this.outer.imgopt.io32.`~alignment~`;
		}
		return ret;
	    }`;
    }/*}}}*/

    /**
     * Structure describing single section in PE header.
     * Structures start after PE Image File + ImageFile.SizeofOptionalHeader.
     * There should be ImageFile.NumberOfSectionHeader structures in file'
     * I've changed this to class, since I need some methods to access
     * ImageOptional header via 'outer' keyword
     *
     */ /*{{{*/
    class ImageSectionHeader {
		char[8] Name;
		uint VirtualSize;
		uint VirtualAddress;
		uint SizeOfRawData;
		uint PointerToRawData;
		uint PointerToRelocations;
		uint PointerToLinenumbers;
		ushort NumberOfRelocations;
		ushort NumberOfLinenumbers;
		uint Characteristics;
	
		uint isCode() { return !!(Characteristics & 0x20); }
		uint isExecutable() { return !!(Characteristics & 0x20000000); }
	
		mixin (AddressRound!("rva", "VirtualAddress",	"SectionAlignment"));
		mixin (SizeRound!   ("vsz", "VirtualSize",		"SectionAlignment"));
		mixin (AddressRound!("raw", "PointerToRawData", "FileAlignment"));
		mixin (SizeRound!   ("rsz", "SizeOfRawData",	"FileAlignment"));
	
		char[] normalizedName()
		{
		    char[] ret = new char[8];
		    for (auto i=0; i<8; i++)
			ret[i] = (Name[i] >= ' ' && Name[i] <= 127)?Name[i]:'×';
		    return ret;
		}
		char[] toString() {
		    Layout!(char) tforma = new Layout!(char)();
		    char[] ret, character;
	
		    ret ~= tforma ("{,35} {}\n", "Name", normalizedName);
		    ret ~= tforma ("{,35} {:x8} {:x8}\n", "VA",		VirtualAddress,	    rva);
		    ret ~= tforma ("{,35} {:x8} {:x8}\n", "VS",		VirtualSize,	    vsz);
		    ret ~= tforma ("{,35} {:x8} {:x8}\n", "RawPoint",	PointerToRawData,   raw);
		    ret ~= tforma ("{,35} {:x8} {:x8}\n", "RawSize",	SizeOfRawData,	    rsz);
	
		    if (isCode) character ~= "  CODE ";
		    else character ~= "nocode ";
	
		    if (isExecutable) character ~= "  EXEC ";
		    else character ~= "noexec ";
	
		    if (Characteristics & 0x80000000) character ~= "  WRIT ";
		    else character ~= "nowrit ";
	
		    ret ~= tforma ("{,35} {:x} {}\n", "Characteristics", Characteristics, character);
	
		    return ret;
		}
    } /*}}}*/

    enum {
		IMAGEOPTIONALMAGICPE32  = 0x10b,
		IMAGEOPTIONALMAGICPE32P = 0x20b
    }

	private {
	    InputStream fp;
	
	    uint imageDos_LFAnew;
	    ushort imageOptional_Magic;
	    bool isPePlus;
	
	    ImageFile imgfile;
	    union {
			ImageOptional32 imgopt32;
			ImageOptional64 imgopt64;
	    }
	    ImageOptional imgopt;
	    ImageSectionHeader[] imgsects;
	    uint lastRVA;
	
	    //ImageImportDescriptor imgimports;
	
	    //MapFile memorymap;
	    //ImageImportLib[] libs;
	}

    this(InputStream lfp)
    {
		fp = lfp;
	
		readLFANew;
		readImageFile;
		readImageOptional;
		readImageSections;
    }

    /**
     * Checks if associated FileConduit
     * has 'MZ' signature ath the beginning,
     * tries to read lfanew value and returns it.
     */
    private void readLFANew()
    {
		ushort imageDos_Magic;
	
		assert (fp);
		assert (imageDos_LFAnew == imageDos_LFAnew.init, "readLFANew() already called!");
	
		auto read = new Reader(fp);
		fp.seek(0);
		read (imageDos_Magic);

                if (imageDos_Magic != 0x5a4d) {
                    throw new PEException("There is no mz magic!");
                }
	
		read = new Reader(fp);
		fp.seek(60);
		read (imageDos_LFAnew);
    }
    uint getLFANew() { return imageDos_LFAnew; }

    /**
     * Read ImageFile structure from associated
     * FileConduit
     */
    private void readImageFile()
    {
		assert (imageDos_LFAnew, "call readLFANew() first!");
		assert (imgfile == imgfile.init, "readImageFile() aldready called!");
	
		auto read = new Reader(fp);
		fp.seek(imageDos_LFAnew);
		mixin ("read " ~ RetriveFields!(ImageFile, "imgfile", 0) ~ ";");
	
		if (imgfile.SizeOfOptionalHeader < ImageOptional32.sizeof)
		{
		    assert (0, "OptionalHeader too small");
		}
	
		if (imgfile.NumberOfSections < 1 || imgfile.NumberOfSections > 100)
		{
		    assert (0, "NumberOfSection field has incorrect value");
		}
		read (imageOptional_Magic);
    }
    ImageFile getImageFile() { return imgfile; }

    /**
     * Tries to recognize whether associated FileConduit is PE or PE+
     * and read proper ImageOptional structure.
     * Return it to the user.
     */
    private void readImageOptional()
    {
		assert (imgfile != imgfile.init, "call readImageFile() first!");
		assert (imgopt == imgopt.init, "readImageOptional() already called!");
	
		auto read = new Reader(fp);
		fp.seek(imageDos_LFAnew + ImageFile.sizeof);
	
		if (imageOptional_Magic == IMAGEOPTIONALMAGICPE32P && imgfile.SizeOfOptionalHeader >= ImageOptional64.sizeof)
		{
		    mixin ("read " ~ RetriveFields!(ImageOptional64, "imgopt64", 0) ~ ";");
		    imgopt.io64 = &imgopt64;
		    imgopt.peio = ImageOptional.PEIO.PEIO64;
		} else {
		    if (imageOptional_Magic == IMAGEOPTIONALMAGICPE32P) {
			Stdout ("ImageOptional Magic value indicates PE32+, but sizeofoptionalheader mismatch, trying read normal header").newline;

		    } else if (imageOptional_Magic != IMAGEOPTIONALMAGICPE32) {
			Stdout ("ImageOptional Magic value is inncorrect, probably broken win95 file").newline;
		    }
		    mixin ("read " ~ RetriveFields!(ImageOptional32, "imgopt32", 0) ~ ";");
		    imgopt.io32 = &imgopt32;
		    imgopt.peio = ImageOptional.PEIO.PEIO32;
		}
    }
    ImageOptional getImageOptional() { return imgopt; }

    /**
     * Read sections from associated FileConduit into an array and return
     * this array to user.
     */
    private void readImageSections()
    {
		assert (imgfile != imgfile.init, "call readImageFile() first!");
		assert (imgopt != imgopt.init, "call readImageOptional() first!");
	
		assert (imgsects.length == 0, "readImageSections already called!");
	
		auto read = new Reader(fp);
		fp.seek(imageDos_LFAnew + ImageFile.sizeof + imgfile.SizeOfOptionalHeader);
	
		for (int i=0; i<imgfile.NumberOfSections; ++i)
		{
		    auto imgsect = new ImageSectionHeader;
		    mixin ("read " ~ RetriveFields!(ImageSectionHeader, "imgsect", 0) ~ ";");
		    imgsects ~= imgsect;
		    with (imgsect)
			if (rva+vsz > lastRVA)
			    lastRVA = rva+vsz;
		}
		assert (lastRVA == imgopt32.SizeOfImage, "rvas fscked up?");
    }
    ImageSectionHeader[] getImageSections() { return imgsects; }

    /**
     * gets as a parameter RVA, and converts it
     * to proper offset in file
     */
    int RVA2Off(uint RVA)
    {
		assert (imgsects.length != 0, "readImageSections not called, there must be at least one section");
		foreach (sect; imgsects)
		    if (sect.rva <= RVA  && RVA < sect.rva+sect.rsz)
		    {
			int ret = RVA - sect.rva + sect.raw;
			Stdout.format ("{:x8} {:x8}", sect.rva, sect.raw).newline;
			assert (ret < sect.raw + sect.rsz, "offset lies beyond the sections physical size");
			return ret;
		    }
		return -1;
    }
}

