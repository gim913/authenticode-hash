import tango.io.device.File;
import tango.io.device.FileMap;
import tango.io.protocol.Reader;
import tango.core.Exception;

import tango.io.FilePath;

import tango.io.Console;
import tango.io.Stdout;
import tango.text.Unicode;
import GMd5;
import tango.util.digest.Sha1;

import Integer = tango.text.convert.Integer;

import PEHeader;

const uint[] oidOiwSecSigAlgorithmSha1     = [1, 3, 14, 3, 2, 26];
const uint[] oidUsRsadsiDigestalgorithmMd5 = [1, 2, 840, 113549, 2, 5];
const uint[] oidUsRsadsiPkcs7SignedData    = [1, 2, 840, 113549, 1, 7, 2];
const uint[] oidMsAuthenticodeSpcindirectdataobjid = [1, 3, 6, 1, 4, 1, 311, 2, 1, 4];
const uint[] oidMsAuthenticodeSpcpeimagedataobjid  = [1, 3, 6, 1, 4, 1, 311, 2, 1, 15];

ubyte[] extractDigest(ubyte[] mem)
{
    enum TagCls { Integer = 2, BitString = 3, OctetString = 4, Null = 5, ObjectIdentifier = 6, Sequence = 16, Set = 17 };

    struct Tag {
        enum { Universal, Application, Context, Personal };
        int cls;
        int isConstructed;
        uint number;
    }
    Tag getTag(ref ubyte *ptr) { // {{{
        Tag ret;
        ret.isConstructed = (*ptr & 0x20);
        ret.cls = (*ptr) >> 6;

        ret.number = (*ptr) & 0x1f;
        if (ret.number == 0x1f) {
            assert(0, "handle this case");
        }

        ++ptr;

        return ret;
    } // }}}

    uint getLen(ref ubyte *ptr) { // {{{
        uint f = *ptr & 0x80;
        uint ret = f ? 0 : (*ptr);
        uint cnt = f ? (*ptr & 0x7f) : 0;
        assert (cnt <= 4, "oh noez, length too big");

        ++ptr;
        version (LittleEndian) {
            while (cnt--) {
                ret <<= 8;
                ret |= *ptr++;
            }
        }
        version (BigEndian) {
            assert(0, "add big-endian support");
        }
        return ret;
    } // }}}

    uint[] hexToOid(ubyte[] q) { // {{{
        uint[] ret;
        ubyte *p = q.ptr;
        ret ~= (*p / 40);
        ret ~= (*p % 40);
        p++;

        while(p < q.ptr + q.length) {
            uint r = 0;
            while ((*p & 0x80)) {
                r += (*p++ & 0x7f);
                assert (r*128 > r, "oid overflow");
                r *= 128;
            }
            assert (r+(*p & 0x7f) > r, "oid overflow");
            r += (*p++ & 0x7f);
            ret ~= r;
        }
        return ret;
    } // }}}

    auto p = mem.ptr;
    auto seq = getTag (p);

    if (TagCls.Sequence != seq.number) {
        Stdout (seq.number).newline;
        assert (0, "unknown tag class");
    }

    auto seqLen = getLen(p);
    assert (seqLen <= mem.ptr - p + mem.length);

    auto obj = getTag (p);
    auto objLen = getLen(p);
    assert (obj.number == TagCls.ObjectIdentifier, "unknown tag class");

    auto oid = hexToOid(p[0 .. objLen]);
    p += objLen;

    if (oid != oidUsRsadsiPkcs7SignedData) {
        assert(0, "signedData oid not found");
    }
    
    auto el = getTag (p);
    auto elLen = getLen (p);
    assert (Tag.Context == el.cls && el.isConstructed && 0 == el.number, "unexpected tag");

    seq = getTag (p);
    seqLen = getLen (p);
    assert (TagCls.Sequence == seq.number, "unknown tag class");

    obj = getTag(p);
    objLen = getLen(p);
    assert (TagCls.Integer == obj.number, "unknown tag class");
    assert (1 == objLen, "SignedData.version length != 1");
    uint ver = *p++;
    assert (1 == ver, "SignedData.version must equal 1");

    // DigestAlgorithmIdentifiers
    obj = getTag(p);
    objLen = getLen(p);
    assert (TagCls.Set == obj.number, "unknown tag class");

    seq = getTag(p);
    seqLen = getLen(p);
    assert (TagCls.Sequence == seq.number, "unknown tag class");

    uint[] selectedDigestAlgorithm = null; 
    while (1) {
        obj = getTag (p);
        objLen = getLen(p);
        if (Tag.Universal == obj.cls && TagCls.Null == obj.number) {
            break;
        }
        assert (obj.number == TagCls.ObjectIdentifier, "unknown tag class");

        oid = hexToOid(p[0 .. objLen]);
        p += objLen;

        assert (selectedDigestAlgorithm is null, "Authenticode supports only one Signer");
        if (oid == oidUsRsadsiDigestalgorithmMd5) {
            selectedDigestAlgorithm = oidUsRsadsiDigestalgorithmMd5;

        } else if (oid == oidOiwSecSigAlgorithmSha1) {
            selectedDigestAlgorithm = oidOiwSecSigAlgorithmSha1;
        }
    }

    // ContentInfo
    seq = getTag (p);
    seqLen = getLen(p);
    assert (TagCls.Sequence == seq.number, "unknown tag class");

    obj = getTag (p);
    objLen = getLen(p);
    assert (obj.number == TagCls.ObjectIdentifier, "unknown tag class");

    oid = hexToOid(p[0 .. objLen]);
    p += objLen;
    if (oid != oidMsAuthenticodeSpcindirectdataobjid) {
        assert(0, "SpcIndirectDataObjId oid not found");
    }

    // SpcIndirectDataContent
    el = getTag (p);
    elLen = getLen (p);
    assert (Tag.Context == el.cls && el.isConstructed && 0 == el.number, "unexpected tag");

    seq = getTag(p);
    seqLen = getLen(p);
    assert (TagCls.Sequence == seq.number, "unknown tag class");
     
    if (1) {
        // SpcAttributeTypeAndOptionalValue
        seq = getTag(p);
        seqLen = getLen(p);
        assert (TagCls.Sequence == seq.number, "unknown tag class");
        if (1) {

            // type
            obj = getTag(p);
            objLen = getLen(p);
            assert (TagCls.ObjectIdentifier == obj.number, "unknown tag class");

            oid = hexToOid(p[0 .. objLen]);
            p += objLen;
            if (oid != oidMsAuthenticodeSpcpeimagedataobjid) {
                assert(0, "SpcPeImageDataObjId oid not found");
            }

            // value = SpcPeImageData
            seq = getTag(p);
            seqLen = getLen(p);
            assert (TagCls.Sequence == seq.number, "unknown tag class");
            if (1) { 

                // SpcPeImageFlags
                obj = getTag(p);
                objLen = getLen(p);
                assert (TagCls.BitString  == obj.number, "unknown tag class");
                assert (*p == 0, "empty bitstring expected");
                p++;

                // SpcLink (file)
                el = getTag (p);
                elLen = getLen (p);
                assert (Tag.Context == el.cls && el.isConstructed && 0 == el.number, "unexpected tag");
                if (1) {
             
                    // SpcLink
                    el = getTag (p);
                    elLen = getLen (p);
                    assert (Tag.Context == el.cls && el.isConstructed, "unexpected tag");

                    /// file[2]
                    if (2 == el.number) {
                        // get inner elem
                        el = getTag (p);
                        elLen = getLen (p);
                        assert (Tag.Context == el.cls && !el.isConstructed && 0 == el.number, "unexpected tag");
                        version (Debug) {
                            wchar[] w;
                            foreach (temp; cast(ushort[])p[0 .. elLen]) {
                                temp = (temp >> 8) | (temp << 8);
                                w ~= temp;
                            }
                            Stdout (w).newline;
                        }
                        p += elLen;

                    // moniker[1]
                    } else if (1 == el.number) {
                        p += elLen;

                    } else {
                        assert (0, "unexpected tag");
                    }
                }
            }
        }

        // DigestInfo
        seq = getTag(p);
        seqLen = getLen(p);
        assert (TagCls.Sequence == seq.number, "unknown tag class");
        if (1) {
            // AlgorithmIdentifier
            seq = getTag(p);
            seqLen = getLen(p);
            assert (TagCls.Sequence == seq.number, "unknown tag class");
            if (1) {
                obj = getTag(p);
                objLen = getLen(p);
                assert (TagCls.ObjectIdentifier == obj.number, "unknown tag class");

                oid = hexToOid(p[0 .. objLen]);
                p += objLen;
                if (oid != selectedDigestAlgorithm) {
                    assert(0, "digest algorithm mismatch");
                }

                obj = getTag (p);
                objLen = getLen(p);
                assert (Tag.Universal == obj.cls && TagCls.Null == obj.number, "Null value expected");
            }
            
            // OCTETSTRING
            obj = getTag(p);
            objLen = getLen(p);
            assert (TagCls.OctetString  == obj.number, "unknown tag class");

            return p[0 .. objLen];
        }
    }
    return mem;
}

int prepare(PEHeader peh, ubyte[] mem)
{ // {{{
    ushort* sig = cast(ushort*)mem.ptr;
    uint lfanew = *cast(uint*)(mem.ptr + 0x3c);
    ubyte[] peStart;

    // checks stolen from win .dll
    // ZM
    if (*sig != 0x5a4d) {
        return -1;
    }

    if (lfanew == 0 || lfanew >= mem.length) {
        return -1;
    }

    // 0xe0 + 0x14 + 0x4
    if ( (mem.length - lfanew) < 0xf8) {
        return -1;
    }

    peStart = mem[lfanew..$];

    // all mz header is in mem and pe starts after mz header
    if ((peStart.ptr + 0xf8 > mem.ptr + mem.length) || (peStart.ptr < mem.ptr + 0x40)) {
        return -1;
    }
    // mz header AND pe header are in mem
    if ((peStart.ptr - mem.ptr + 0xf8) > mem.length) {
        return -1;
    }
    // 'PE\0\0' and SizeOfOptionalHeader != 0
    if ((*cast(uint*)(peStart.ptr) != 0x4550) || peh.getImageFile.SizeOfOptionalHeader == 0) {
        return -1;
    }

    PEHeader.PEHeader.ImageDataDir sdd;
    if (peh.getImageOptional.io32.Magic == 0x10b) {
        //ubyte* sects = peStart.ptr + peh.getImageFile.SizeOfOptionalHeader;
        //uint sizeOfSects = 0x28 * peh.getImageFile.NumberOfSections;
        //if (sects + sizeOfSects > sects && sects + sizeOfSects < mem.ptr + mem.length) {
        if (peh.getImageOptional.io32.NumberOfRvaAndSizes >= 5) {
            sdd = peh.getImageOptional.io32.DataDirectory[4];
        }
        //}
    } else {
        return -2;
    }

    // this is in fact offset not a VA
    auto sddOffset = sdd.VirtualAddress;
    if (sddOffset > mem.length || sdd.Size < 8 || sddOffset + sdd.Size > mem.length) {
        return -1;
    }

    if (sddOffset + sdd.Size < sddOffset || sddOffset < peh.getImageOptional.io32.SizeOfHeaders) {
        return -1;
    }

    foreach (sect; peh.getImageSections) {
        // off must not be inside of dny of sections (aligned off + unligned size)
        if (sddOffset < sect.raw + sect.SizeOfRawData) {
            return -1;
        }
    }
    
    auto checkSumOff = lfanew + 0x58;
    auto checkSumSize = checkSumOff + 4;
    auto sddOff = lfanew + 0x98; // pe32
    auto sddSize = sddOff + 8;

    auto slice1 = mem[0 .. checkSumOff];
    auto slice2 = mem[checkSumSize .. sddOff];
    auto slice3 = mem[sddSize .. sddOffset];
    auto slice4 = mem[sddOffset + sdd.Size .. $];

    auto size     = *cast(uint*)(mem.ptr + sddOffset);
    auto revision = *cast(ushort*)(mem.ptr + sddOffset + 4);
    auto certType = *cast(ushort*)(mem.ptr + sddOffset + 6);
    assert (size == sdd.Size, "cert size mismatch");
    assert (revision == 0x200, "bad revision"); // WIN_CERT_VERSION_2_0
    assert (certType == 0x002, "unknown cert type"); // WIN_CERT_TYPE_PKCS_SIGNED_DATA

    auto digest = extractDigest( mem[sddOffset + 8 .. sddOffset + sdd.Size] );

    if (digest.length == 20) {
        auto sh1 = new Sha1();
        sh1.update(slice1);
        ubyte temp[20];
        version (Debug) {
            sh1.createDigest(temp);
            Stdout.format ("sha.a: {:x}", slice1.length);
            foreach (b; temp)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;
        }

        sh1.update(slice2);
        version (Debug) {
            sh1.createDigest(temp);
            Stdout.format ("sha.b: {:x}", slice2.length);
            foreach (b; temp)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;
        }
        sh1.update(slice3);
        version (Debug) {
            sh1.createDigest(temp);
            Stdout.format ("sha.c: {:x}", slice3.length);
            foreach (b; temp)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;
        }
        sh1.update(slice4);
        version (Debug) {
            sh1.createDigest(temp);
            Stdout.format ("sha.d: {:x}", slice4.length);
            foreach (b; temp)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;
        }

        auto digestSha = sh1.binaryDigest;
        
        version (Debug) {
            Stdout ("sha: ");
            foreach (b; digestSha)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;

            Stdout ("org: ");
            foreach (b; digest)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;
        }

        if (digest == digestSha) {
            Stdout ("sha matches").newline;

        } else {
            Stdout ("sha MISMATCH").newline;
        }
 
    } else {
        auto md5 = new Md5();
        md5.update(slice1);
        md5.update(slice2);
        md5.update(slice3);
        md5.update(slice4);

        auto digestMd5 = md5.binaryDigest;

        version (Debug) {
            Stdout ("md5: ");
            foreach (b; digestMd5)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;

            Stdout ("org: ");
            foreach (b; digest)
                Stdout.format ("{:x2} ", b);
            Stdout.newline;
        }

        if (digest == digestMd5) {
            Stdout ("md5 matches").newline;

        } else {
            Stdout ("md5 MISMATCH").newline;
        }
    }

    return -1;
} // }}}

int main(char args[][])
{
    assert (args.length > 1);
    Stdout (args[1]) .newline;
    auto myself_data = new FileMap(args[1], File.ReadExisting);
    auto peh = new PEHeader(myself_data);
    
    //Stdout (peh.getImageFile).newline;

    myself_data.seek(0);
    prepare (peh, cast(ubyte[])(myself_data.slice()));

    return 0;
}
