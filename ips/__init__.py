import struct
import io

def unpack_file(fmt, f):
    ret = struct.unpack(fmt, f.read(struct.calcsize(fmt)))

    if len(ret) == 1:
        return ret[0]
    return ret

class Patch:
    class Record:
        def __init__(self, patch, offset, cont, rle_size=-1):
            if rle_size >= 0 and len(cont) != 1:
                raise ValueError("Invalid content for an RLE record")

            if (not patch.ips32 and offset > 0xFFFFFF) or (patch.ips32 and offset > 0xFFFFFFFF):
                    raise ValueError("Offset is too large for patch format")

            if rle_size > 0xFFFF: # If the RLE size can't fit in 16 bits
                raise ValueError("RLE size is too large")

            if rle_size < 0 and len(cont) > 0xFFFF: # If the size can't fit in 16 bits
                raise ValueError("Length of content is too large")

            self.patch = patch
            self.offset = offset
            self.cont = cont
            self.rle_size = rle_size

        def __bytes__(self):
            buf = b""

            buf += struct.pack(">I", self.offset)
            if not self.patch.ips32:
                buf = buf[1:]

            if self.rle_size >= 0:
                buf += struct.pack(">HH", 0, self.rle_size)
            else:
                buf += struct.pack(">H", len(self.cont))

            buf += self.cont

            return buf

        def __eq__(self, other):
            ret = self.offset == other.offset and self.cont == other.cont

            if self.rle_size > 0 or other.rle_size > 0:
                if self.rle_size != other.rle_size:
                    return False

            return ret

    def __init__(self, ips32=False):
        self.ips32 = ips32

        self.records = []

    @property
    def header(self):
        return b"IPS32" if self.ips32 else b"PATCH"

    @property
    def tail(self):
        return b"EEOF" if self.ips32 else b"EOF"

    def add_record(self, offset, cont, rle_size=-1):
        self.records.append(self.Record(self, offset, cont, rle_size))

    def apply(self, old_f, new_f):
        if isinstance(old_f, (bytes, bytearray)):
            old_f = io.BytesIO(old_f)

        new_f.seek(0)
        curr_off = 0
        for r in self.records:
            old_f.seek(curr_off)
            new_f.write(old_f.read(r.offset - curr_off))

            if r.rle_size >= 0:
                new_f.write(r.cont * r.rle_size)
            else:
                new_f.write(r.cont)

            curr_off = new_f.tell()

        old_f.seek(curr_off)
        new_f.write(old_f.read())

    def __bytes__(self):
        buf = b""

        buf += self.header

        for r in self.records:
            buf += bytes(r)

        buf += self.tail

        return buf

    def __eq__(self, other):
        for r1, r2 in zip(self.records, other.records):
            if r1 != r2:
                return False

        return self.ips32 == other.ips32

    @classmethod
    def load(cls, f):
        if isinstance(f, (bytes, bytearray)):
            f = io.BytesIO(f)

        header = unpack_file("5s", f)

        if header == b"IPS32":
            ips32 = True
        elif header == b"PATCH":
            ips32 = False
        else:
            raise ValueError("Invalid header for an IPS patch")

        p = cls(ips32)

        while True:
            offset = unpack_file(f"{len(p.tail)}s", f)
            if offset == p.tail:
                return p

            if ips32:
                offset = struct.unpck(">I", offset)[0]
            else:
                offset = struct.unpack(">I", b"\x00" + offset)[0]

            size = unpack_file(">H", f)

            rle_size = -1
            if size == 0:
                rle_size, cont = unpack_file(">Hc", f)
            else:
                cont = unpack_file(f"{size}s", f)

            p.add_record(offset, cont, rle_size)

    @classmethod
    def create(cls, old_f, new_f):
        """
        Logic taken from https://github.com/Alcaro/Flips/
        """

        if isinstance(old_f, (bytes, bytearray)):
            old_f = io.BytesIO(old_f)
        if isinstance(new_f, (bytes, bytearray)):
            new_f = io.BytesIO(new_f)

        p = cls()

        old_f.seek(0, 2)
        old_len = old_f.tell()
        old_f.seek(0)

        new_f.seek(0, 2)
        new_len = new_f.tell()
        new_f.seek(0)

        offset = 0
        last_change = 0

        while offset < new_len:
            new_f.seek(offset)
            old_f.seek(offset)

            while offset < old_len and old_f.read(1) == new_f.read(1):
                offset += 1

            size = max(0, last_change - offset)
            unchanged_len = 0

            while True:
                new_f.seek(offset + size + unchanged_len)
                old_f.seek(new_f.tell())

                if new_f.tell() < old_len and old_f.read(1) == new_f.read(1):
                    unchanged_len += 1
                else:
                    size += unchanged_len + 1
                    unchanged_len = 0

                if unchanged_len >= 6 or size >= 0xFFFF:
                    break

            if offset > 0xFFFFFF:
                p.ips32 = True

            if (not p.ips32 and offset == 0x454f46) or (p.ips32 and offset == 0x45454f46): # Offset is EOF or EEOF
                offset -= 1
                size += 1

            last_change = offset + size
            size = min(size, 0xFFFF)

            if offset + size > new_len:
                size = new_len - offset

            if offset == new_len:
                break

            new_f.seek(offset)
            same_byte = new_f.read(1)
            
            same_len = 1
            while same_len < size and same_byte == new_f.read(1):
                same_len += 1

            if same_len == size:
                i = 0
                while True:
                    pos = offset + same_len + i - 1
                    new_f.seek(pos)
                    old_f.seek(pos)
                    
                    if pos >= new_len or new_f.read(1) != same_byte or same_len + i > 0xFFFF:
                        break

                    if pos >= old_len or old_f.read(1) != same_byte:
                        same_len += i
                        size += i
                        i = 0

                    i += 1

            if (same_len > 3 and same_len == size) or same_len > 8:
                p.add_record(offset, same_byte, same_len)
                offset += same_len
            else:
                same_len = 0
                stop_at = 0
                while stop_at + same_len < size:
                    new_f.seek(offset + stop_at)
                    b1 = new_f.read(1)

                    new_f.seek(offset + stop_at + same_len)
                    b2 = new_f.read(1)

                    if b1 == b2:
                        same_len += 1
                    else:
                        stop_at += same_len
                        same_len = 0

                    new_f.seek(offset + stop_at + same_len)
                    b1 = new_f.read(8)

                    new_f.seek(offset + stop_at + same_len + 1)
                    b2 = new_f.read(8)

                    if same_len > 13 or (same_len > 8 and (stop_at + same_len == size or b1 == b2)):
                        if stop_at > 0:
                            size = stop_at
                        
                        break

                if offset + size != new_len:
                    while offset + size - 1 < old_len:
                        new_f.seek(offset + size - 1)
                        old_f.seek(offset + size - 1)
                        if new_f.read(1) == old_f.read(1):
                            size -= 1
                        else:
                            break

                new_f.seek(offset)
                b1 = new_f.read(size - 1)

                new_f.seek(offset + 1)
                b2 = new_f.read(size - 1)

                if size > 3 and b1 == b2:
                    p.add_record(offset, same_byte, size)
                else:
                    new_f.seek(offset)
                    p.add_record(offset, new_f.read(size))

                offset += size

        return p