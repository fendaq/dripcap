import {Layer, Item, Value} from 'dripcap';
import MACAddress from 'driptool/mac';
import {IPv4Address} from 'driptool/ipv4';

export default class ARPDissector {
  static get namespaces() {
    return ['::Ethernet::<ARP>'];
  }

  analyze(packet, parentLayer) {
    let layer = {
      items: []
    };
    layer.namespace = '::Ethernet::ARP';
    layer.name = 'ARP';
    layer.id = 'arp';

    let htypeNumber = parentLayer.payload.readUInt16BE(0);
    layer.items.push({
      name: 'Hardware type',
      id: 'htype',
      range: '0:2',
      value: htypeNumber,
      items: [
        {
          name: 'Name',
          id: 'name',
          range: '0:2',
          value: hardwareTable[htypeNumber]
        }
      ]
    });

    let ptypeNumber = parentLayer.payload.readUInt16BE(2);
    layer.items.push({
      name: 'Protocol type',
      id: 'ptype',
      range: '2:4',
      value: ptypeNumber,
      items: [
        {
          name: 'Name',
          id: 'name',
          range: '2:4',
          value: protocolTable[ptypeNumber]
        }
      ]
    });

    let hlen = parentLayer.payload.readUInt8(4);
    layer.items.push({
      name: 'Hardware length',
      id: 'hlen',
      range: '4:5',
      value: hlen
    });

    let plen = parentLayer.payload.readUInt8(5);
    layer.items.push({
      name: 'Protocol length',
      id: 'plen',
      range: '5:6',
      value: plen
    });

    let operationNumber = parentLayer.payload.readUInt16BE(6);
    let operation = operationNumber;
    let operationName = operationTable[operationNumber];
    layer.items.push({
      name: 'Operation',
      id: 'operation',
      range: '6:8',
      value: operation,
      items: [
        {
          name: 'Name',
          id: 'name',
          range: '6:8',
          value: operationName
        }
      ]
    });

    let sha = MACAddress(parentLayer.payload.slice(8, 14));
    layer.items.push({
      name: 'Sender hardware address',
      id: 'sha',
      range: '8:14',
      value: sha
    });

    let spa = IPv4Address(parentLayer.payload.slice(14, 18));
    layer.items.push({
      name: 'Sender protocol address',
      id: 'spa',
      range: '14:18',
      value: spa
    });

    let tha = MACAddress(parentLayer.payload.slice(18, 24));
    layer.items.push({
      name: 'Target hardware address',
      id: 'tha',
      range: '18:24',
      value: tha
    });

    let tpa = IPv4Address(parentLayer.payload.slice(24, 28));
    layer.items.push({
      name: 'Target protocol address',
      id: 'tpa',
      range: '24:28',
      value: tpa
    });

    layer.summary = `[${operationName.toUpperCase()}] ${sha.data}-${spa.data} -> ${tha.data}-${tpa.data}`;

    return new Layer(layer);
  }
}

let hardwareTable = {
  0x1: 'Ethernet'
};

let protocolTable = {
  0x0800: 'IPv4',
  0x86DD: 'IPv6'
};

let operationTable = {
  0x1: 'request',
  0x2: 'reply'
};
