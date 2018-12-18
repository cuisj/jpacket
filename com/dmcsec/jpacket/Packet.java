package com.dmcsec.jpacket;

public class Packet {
    public class IP {
        public byte     version;
        public byte     ihl;
        public byte     tos;
        public int      tot_len;    // uint16_t
        public short    id;
        public short    frag_off;
        public short    ttl;        // uint8_t
        public short    protocol;  // uint8_t
        public short    check;
        public int      saddr;
        public int      daddr;
    }

    public class TCP {
        public int      source;     // uint16_t
        public int      dest;       // uint16_t
        public long     seq;        // uint32_t
        public long     ack_seq;    // uint32_t
        public byte     doff;
        public byte     res1;
        public byte     cwr;
        public byte     ecn;
        public byte     urg;
        public byte     ack;
        public byte     psh;
        public byte     rst;
        public byte     syn;
        public byte     fin;
        public int      window;     // uint16_t
        public short    check;
        public short    urg_ptr;
    }

    public IP decodeIP(byte[] data, int offset, int length) {
        if (length < 20)
            return null;

        IP ip = new IP();

        ip.version = (byte)((data[offset] & 0xF0) >> 4);
        ip.ihl = (byte)((data[offset] & 0xF) << 2);
        ip.tos = (byte)(data[offset + 1] & 0xFF);
        ip.tot_len = (int)((data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF));
        ip.id = (short)((data[offset + 4] & 0xFF) << 8 | (data[offset + 5] & 0xFf));
        ip.frag_off = (short)((data[offset + 6] & 0xFF) << 8 | (data[offset + 7] & 0xFF));
        ip.ttl = (short)(data[offset + 8] & 0xFF);
        ip.protocol = (short)(data[offset + 9] & 0xFF);
        ip.check = (short)((data[offset + 10] & 0xFF) << 8 | (data[offset + 11] & 0xFF));
        ip.saddr = (int)((data[offset + 12] & 0xFF) << 24 | (data[offset + 13] & 0xFF) << 16 | (data[offset + 14] & 0xFF) << 8 | (data[offset + 15] & 0xFF));
        ip.daddr = (int)((data[offset + 16] & 0xFF) << 24 | (data[offset + 17] & 0xFF) << 16 | (data[offset + 18] & 0xFF) << 8 | (data[offset + 19] & 0xFF));

        return ip;
    }

    public TCP decodeTCP(byte[] data, int offset, int length) {
        if (length < 20)
            return null;

        TCP tcp  = new TCP();

        tcp.source = (int)((data[offset] & 0xFF) << 8 | (data[offset + 1] & 0xFF));
        tcp.dest = (int)((data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF));
        tcp.seq = (int)((data[offset + 4] & 0xFF) << 24 | (data[offset + 5] & 0xFF) << 16 | (data[offset + 6] & 0xFF) << 8 | (data[offset + 7] & 0xFF));
        tcp.ack_seq = (int)((data[offset + 8] & 0xFF) << 24 | (data[offset + 9] & 0xFF) << 16 | (data[offset + 10] & 0xFF) << 8 | (data[offset + 11] & 0xFF));
        tcp.doff = (byte)(((data[offset + 12] & 0xF0) >> 4) << 2);
        tcp.res1 = (byte)(data[offset + 12] & 0xF);
        tcp.cwr = (byte)((data[offset + 13] & 0x80) >> 7);
        tcp.ecn = (byte)((data[offset + 13] & 0x40) >> 6);
        tcp.urg = (byte)((data[offset + 13] & 0x20) >> 5);
        tcp.ack = (byte)((data[offset + 13] & 0x10) >> 4);
        tcp.psh = (byte)((data[offset + 13] & 0x8) >> 3);
        tcp.rst = (byte)((data[offset + 13] & 0x4) >> 2);
        tcp.syn = (byte)((data[offset + 13] & 0x2) >> 1);
        tcp.fin = (byte)(data[offset + 13] & 0x1);
        tcp.window = (int)((data[offset + 14] & 0xFF) << 8 | data[offset + 15] & 0xFF);
        tcp.check = (short)((data[offset + 16] & 0xFF) << 8 | data[offset + 17] & 0xFF);
        tcp.urg_ptr = (short)((data[offset + 18] & 0xFF) << 8 | data[offset + 19] & 0xFF);

        return tcp;
    }


    private long partCksum(long initcksum, byte[] data, int offset, int length) {
        long cksum;
        int idx;
        int odd;

        cksum = initcksum;

        odd = length & 1;
        length -= odd;

        for (idx = 0; idx < length; idx += 2) {
            cksum += (data[offset + idx] & 0xFF) << 8 | (data[offset + idx +1] & 0xFF);
        }

        if (odd != 0) {
            cksum += (data[offset + idx] & 0xFF) << 8;
        }

        while ((cksum >> 16) != 0) {
            cksum = (cksum &0xFFFF) + (cksum >> 16);
        }

        return cksum;
    }

    public void recalcIPCheckSum(byte[] data, int offset, int length) {
        long answer;

        if (length < 20)
            return;

        data[offset + 10] = 0;
        data[offset + 11] = 0;
        answer = partCksum(0, data, offset, length);
        answer = ~answer & 0xFFFF;

        data[offset + 10] = (byte)((answer & 0xFF00) >> 8);
        data[offset + 11] = (byte)((answer & 0xFF));
    }

    public void recalcTCPCheckSum(byte[] data, int offset, int length) {
        long calccksum;

        int ipTotLen = (int)((data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF));

        int tcpOffset = offset + ((data[offset] & 0xF) << 2);
        int tcpLen = ipTotLen - ((data[offset] & 0xF) << 2);

        if (length < ipTotLen)
            return;

        byte[] phdr = new byte[4];
        phdr[0] = 0;
        phdr[1] = 6;
        phdr[2] = (byte)((tcpLen >> 8) & 0xFF);
        phdr[3] = (byte)((tcpLen & 0xFF));

        data[tcpOffset + 16] = 0;
        data[tcpOffset + 17] = 0;

        calccksum = partCksum(0L, data, offset + 12,4);
        calccksum = partCksum(calccksum, data, offset + 16,4);
        calccksum = partCksum(calccksum, phdr, 0, 4);
        calccksum = partCksum(calccksum, data, tcpOffset, tcpLen);
        calccksum = ~calccksum & 0xFFFF;

        data[tcpOffset + 16] = (byte)((calccksum & 0xFF00) >> 8);
        data[tcpOffset + 17] = (byte)((calccksum & 0xFF));
    }
}
