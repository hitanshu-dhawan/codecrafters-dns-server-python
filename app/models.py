from dataclasses import dataclass
import struct
import ipaddress

@dataclass
class Header:
    """
    Represents the DNS packet header with all specified fields.
    
    Attributes:
    - id: Packet identifier (16 bits)
    - qr: Query/Response Indicator (1 bit)
    - opcode: Operation Code (4 bits)
    - aa: Authoritative Answer (1 bit)
    - tc: Truncation (1 bit)
    - rd: Recursion Desired (1 bit)
    - ra: Recursion Available (1 bit)
    - z: Reserved bits (3 bits)
    - rcode: Response Code (4 bits)
    - qdcount: Question Count (16 bits)
    - ancount: Answer Record Count (16 bits)
    - nscount: Authority Record Count (16 bits)
    - arcount: Additional Record Count (16 bits)
    """
    
    id: int = 0
    qr: int = 0
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 0
    ra: int = 0
    z: int = 0
    rcode: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0
    
    def encode(self) -> bytes:
        """
        Encode the DNS header into a 12-byte binary format.
        
        Returns:
        bytes: 12-byte representation of the DNS header
        """

        # Combine flags into a single 16-bit value
        flags = (
            (self.qr << 15) |
            (self.opcode << 11) |
            (self.aa << 10) |
            (self.tc << 9) |
            (self.rd << 8) |
            (self.ra << 7) |
            (self.z << 4) |
            self.rcode
        )
        
        # Pack all fields into 12 bytes using big-endian format
        return struct.pack(
            '!HHHHHH', 
            self.id,          # Packet Identifier
            flags,            # Flags and response code
            self.qdcount,     # Question Count
            self.ancount,     # Answer Count
            self.nscount,     # Authority Count
            self.arcount      # Additional Count
        )
    
    @classmethod
    def decode(cls, data: bytes) -> 'Header':
        """
        Decode a 12-byte binary representation into a Header object.
        
        Args:
        data (bytes): 12-byte DNS header in binary format
        
        Returns:
        Header: Decoded DNS header object
        """

        # Unpack the 12 bytes into 6 16-bit integers
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data)
        
        # Extract individual flag bits
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        
        # Create and return a new Header object with decoded values
        return cls(
            id=id,
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            z=z,
            rcode=rcode,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount
        )


@dataclass
class Question:
    """
    Represents a DNS Question section.

    Attributes:
    - qname: Domain name (as a string, e.g., "codecrafters.io")
    - qtype: Type of record (e.g., 1 for A record)
    - qclass: Class of record (e.g., 1 for IN)
    """

    qname: str
    qtype: int
    qclass: int

    def encode_name(self) -> bytes:
        """
        Encode the domain name into DNS label format.

        Returns:
        bytes: Encoded domain name.
        """

        labels = self.qname.split(".")
        encoded_name = b"".join(len(label).to_bytes(1, 'big') + label.encode() for label in labels)
        return encoded_name + b"\x00"  # Null terminator

    def encode(self) -> bytes:
        """
        Encode the Question section into a binary format.

        Returns:
        bytes: Binary representation of the Question section.
        """
        return self.encode_name() + struct.pack("!HH", self.qtype, self.qclass)
    
    @classmethod
    def decode(cls, data: bytes, offset: int) -> tuple['Question', int]:
        """
        Decode the Question section from binary data, handling name compression.

        Args:
        - data (bytes): The DNS packet.
        - offset (int): The offset where the question section starts.

        Returns:
        - Question: The decoded question section.
        - int: The new offset after reading the question section.
        """

        qname_parts = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            
            if (length & 0xC0) == 0xC0:  # Check for compression pointer
                pointer_offset = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF  # Mask to get offset
                offset += 2
                temp_offset = pointer_offset
                while True:
                    length = data[temp_offset]
                    if length == 0:
                        break
                    temp_offset += 1
                    qname_parts.append(data[temp_offset:temp_offset+length].decode())
                    temp_offset += length
                break
            else:
                offset += 1
                qname_parts.append(data[offset:offset+length].decode())
                offset += length

        qname = ".".join(qname_parts)
        qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
        offset += 4

        return cls(qname=qname, qtype=qtype, qclass=qclass), offset


@dataclass
class Answer:
    """
    Represents a DNS Answer section.

    Attributes:
    - name: Domain name as a string (e.g., "codecrafters.io").
    - type: Record type (1 for A records).
    - class_: Record class (1 for IN - Internet).
    - ttl: Time-To-Live value in seconds.
    - rdata: The IPv4 address as a string (e.g., "8.8.8.8").
    """

    name: str
    type: int
    class_: int
    ttl: int
    rdata: str

    def encode_name(self) -> bytes:
        """
        Encode the domain name into DNS label format.

        Returns:
        bytes: Encoded domain name.
        """

        labels = self.name.split(".")
        encoded_name = b"".join(len(label).to_bytes(1, 'big') + label.encode() for label in labels)
        return encoded_name + b"\x00"  # Null terminator

    def encode_rdata(self) -> bytes:
        """
        Encode the IPv4 address into a 4-byte big-endian format.

        Returns:
        bytes: Encoded IPv4 address.
        """
        return ipaddress.IPv4Address(self.rdata).packed

    def encode(self) -> bytes:
        """
        Encode the Answer section into a binary format.

        Returns:
        bytes: Binary representation of the Answer section.
        """
        
        rdata_bytes = self.encode_rdata()
        return (
            self.encode_name() +
            struct.pack("!HHI", self.type, self.class_, self.ttl) +
            struct.pack("!H", len(rdata_bytes)) +  # RDLENGTH
            rdata_bytes  # RDATA (IPv4 address)
        )

    @classmethod
    def decode(cls, data: bytes, offset: int) -> tuple['Answer', int]:
        """
        Decode the Answer section from binary data.

        Args:
        - data (bytes): The DNS packet.
        - offset (int): The offset where the answer section starts.

        Returns:
        - Answer: The decoded answer section.
        - int: The new offset after reading the answer section.
        """
        
        # Decode the domain name (without compression handling)
        name_parts = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            
            offset += 1
            name_parts.append(data[offset:offset+length].decode())
            offset += length
        
        name = ".".join(name_parts)
        
        # Read fixed-length fields (Type, Class, TTL, RDLENGTH)
        type, class_, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        
        # Read RDATA (IPv4 address)
        rdata = str(ipaddress.IPv4Address(data[offset:offset+rdlength]))
        offset += rdlength
        
        return cls(name=name, type=type, class_=class_, ttl=ttl, rdata=rdata), offset
