import com.dmcsec.jpacket.Packet;

public class Main {

    public static void main(String[] args) {
        byte packet[] = {   0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00,
                            0x40, 0x06, 0x73, (byte)0xc1, (byte)0xac, 0x10, 0x00, 0x02,
                            0x0a, 0x15, 0x10, (byte)0xd0, (byte)0xd8, 0x2b, 0x1f, 0x40,
                            0x53, 0x03, 0x22, (byte)0xac, 0x00, 0x00, 0x00, 0x00,
                            (byte)0xb0, (byte)0xc2, (byte)0xff, (byte)0xff, 0x6e, 0x17, 0x00, 0x00,
                            0x02, 0x04, 0x05, (byte)0xb0, 0x01, 0x03, 0x03, 0x06,
                            0x01, 0x01, 0x08, 0x0a, 0x25, 0x7c, 0x6e, (byte)0x9a,
                            0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00};

        Packet p = new Packet();
        Packet.IP ip = p.decodeIP(packet, 0, packet.length);

        System.out.format("version: %d\n", ip.version);
        System.out.format("ihl: %d\n", ip.ihl);
        System.out.format("tos: %X\n", ip.tos);
        System.out.format("tot_len: %d\n", ip.tot_len);
        System.out.format("id: %X\n", ip.id);
        System.out.format("frag_off: %X\n", ip.frag_off);
        System.out.format("ttl: %d\n", ip.ttl);
        System.out.format("protocol: %d\n", ip.protocol);
        System.out.format("check: %X\n", ip.check);
        System.out.format("saddr: %X\n", ip.saddr);
        System.out.format("daddr: %X\n", ip.daddr);

        Packet.TCP tcp = p.decodeTCP(packet, ip.ihl, packet.length - ip.ihl);
        System.out.format("source: %d\n", tcp.source);
        System.out.format("dest: %d\n", tcp.dest);
        System.out.format("seq: %d\n", tcp.seq);
        System.out.format("ack_seq: %d\n", tcp.ack_seq);
        System.out.format("doff: %d\n", tcp.doff);
        System.out.format("res1: %X\n", tcp.res1);
        System.out.format("cwr: %d\n", tcp.cwr);
        System.out.format("ecn: %d\n", tcp.ecn);
        System.out.format("urg: %d\n", tcp.urg);
        System.out.format("ack: %d\n", tcp.ack);
        System.out.format("psh: %d\n", tcp.psh);
        System.out.format("rst: %d\n", tcp.rst);
        System.out.format("syn: %d\n", tcp.syn);
        System.out.format("fin: %d\n", tcp.fin);
        System.out.format("window: %d\n", tcp.window);
        System.out.format("tcp check: %X\n", tcp.check);
        System.out.format("urg_ptr: %X\n", tcp.urg_ptr);

        p.recalcIPCheckSum(packet, 0, ip.ihl);
        ip = p.decodeIP(packet, 0, packet.length);
        System.out.format("ip check: %X\n", ip.check);

        p.recalcTCPCheckSum(packet, 0, ip.tot_len);
        tcp = p.decodeTCP(packet, ip.ihl, packet.length);
        System.out.format("tcp check: %X\n", tcp.check);
    }
}
