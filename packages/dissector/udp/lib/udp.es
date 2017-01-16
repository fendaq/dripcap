import {Layer, Item, Value} from 'dripcap';
import {IPv4Host} from 'driptool/ipv4';
import {IPv6Host} from 'driptool/ipv6';

export default class UDPDissector {
  static get namespaces() {
    return [/::Ethernet::\w+::<UDP>/];
  }

  analyze(packet, parentLayer) {
    let layer = {
      items: []
    };
    layer.namespace = parentLayer.namespace.replace('<UDP>', 'UDP');
    layer.name = 'UDP';
    layer.id = 'udp';

    let source = parentLayer.payload.readUInt16BE(0);
    layer.items.push({
      name: 'Source port',
      id: 'srcPort',
      range: '0:2',
      value: source
    });

    let destination = parentLayer.payload.readUInt16BE(2);
    layer.items.push({
      name: 'Destination port',
      id: 'dstPort',
      range: '2:4',
      value: destination
    });

    let srcAddr = parentLayer.getValue('src');
    let dstAddr = parentLayer.getValue('dst');
    let src, dst;

    if (srcAddr.type === 'dripcap/ipv4/addr') {
      src = IPv4Host(srcAddr.data, source);
      dst = IPv4Host(dstAddr.data, destination);
    } else if (srcAddr.type === 'dripcap/ipv6/addr') {
      src = IPv6Host(srcAddr.data, source);
      dst = IPv6Host(dstAddr.data, destination);
    }
    layer.items.push({ id: 'src', value: src });
    layer.items.push({ id: 'dst', value: dst });

    let length = parentLayer.payload.readUInt16BE(4);
    layer.items.push({
      name: 'Length',
      id: 'len',
      range: '4:6',
      value: length
    });

    let checksum = parentLayer.payload.readUInt16BE(6);
    layer.items.push({
      name: 'Checksum',
      id: 'checksum',
      range: '6:8',
      value: checksum
    });

    layer.range = '8:'+ length;
    layer.payload = parentLayer.payload.slice(8, length);

    layer.items.push({
      name: 'Payload',
      id: 'payload',
      range: '8:' + length,
      value: layer.payload
    });

    layer.summary = `${src.data} -> ${dst.data}`;
    return new Layer(layer);
  }
}
