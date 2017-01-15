import {Layer, Item, Value, StreamChunk} from 'dripcap';
import Flags from 'driptool/flags';
import {IPv4Host} from 'driptool/ipv4';
import {IPv6Host} from 'driptool/ipv6';

export default class Dissector {
  static get namespaces() {
    return [/::Ethernet::\w+::<TCP>/];
  }

  analyze(packet, parentLayer) {
    let layer = {
      items: []
    };
    layer.namespace = parentLayer.namespace.replace('<TCP>', 'TCP');
    layer.name = 'TCP';
    layer.id = 'tcp';

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

    let srcAddr = parentLayer.item('src');
    let dstAddr = parentLayer.item('dst');
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

    let seq = parentLayer.payload.readUInt32BE(4);
    layer.items.push({
      name: 'Sequence number',
      id: 'seq',
      range: '4:8',
      value: seq
    });

    let ack = parentLayer.payload.readUInt32BE(8);
    layer.items.push({
      name: 'Acknowledgment number',
      id: 'ack',
      range: '8:12',
      value: ack
    });

    let dataOffset = parentLayer.payload.readUInt8(12) >> 4;
    layer.items.push({
      name: 'Data offset',
      id: 'dataOffset',
      range: '12:13',
      value: dataOffset
    });

    let flagValue = parentLayer.payload.readUInt8(13) |
      ((parentLayer.payload.readUInt8(12) & 0x1) << 8);

    let table = {
      'NS':  0x1 << 8,
      'CWR': 0x1 << 7,
      'ECE': 0x1 << 6,
      'URG': 0x1 << 5,
      'ACK': 0x1 << 4,
      'PSH': 0x1 << 3,
      'RST': 0x1 << 2,
      'SYN': 0x1 << 1,
      'FIN': 0x1 << 0,
    };
    let flags = new Flags(table, flagValue);

    layer.items.push({
      name: 'Flags',
      id: 'flags',
      data: '12:14',
      value: flagValue,
      summary: flags.toString(),
      items: [
        {
          name: 'NS',
          id: 'NS',
          range: '12:13',
          value: flags.get('NS')
        },
        {
          name: 'CWR',
          id: 'CWR',
          range: '13:14',
          value: flags.get('CWR')
        },
        {
          name: 'ECE',
          id: 'ECE',
          range: '13:14',
          value: flags.get('ECE')
        },
        {
          name: 'URG',
          id: 'URG',
          range: '13:14',
          value: flags.get('URG')
        },
        {
          name: 'ACK',
          id: 'ACK',
          range: '13:14',
          value: flags.get('ACK')
        },
        {
          name: 'PSH',
          id: 'PSH',
          range: '13:14',
          value: flags.get('PSH')
        },
        {
          name: 'RST',
          id: 'RST',
          range: '13:14',
          value: flags.get('RST')
        },
        {
          name: 'SYN',
          id: 'SYN',
          range: '13:14',
          value: flags.get('SYN')
        },
        {
          name: 'FIN',
          id: 'FIN',
          range: '13:14',
          value: flags.get('FIN')
        }
      ]
    });

    let window = parentLayer.payload.readUInt16BE(14);
    layer.items.push({
      name: 'Window size',
      id: 'window',
      range: '14:16',
      value: window
    });

    let checksum = parentLayer.payload.readUInt16BE(16);
    layer.items.push({
      name: 'Checksum',
      id: 'checksum',
      range: '16:18',
      value: checksum
    });

    let urgent = parentLayer.payload.readUInt16BE(18);
    layer.items.push({
      name: 'Urgent pointer',
      id: 'urgent',
      range: '18:20',
      value: urgent
    });

    let optionDataOffset = dataOffset * 4;
    let optionItems = [];
    let option = {
      name: 'Options',
      range: '20:' + optionDataOffset,
      items: []
    };

    let optionOffset = 20;

    while (optionDataOffset > optionOffset) {
      switch (parentLayer.payload[optionOffset]) {
        case 0:
          optionOffset = optionDataOffset;
          break;

        case 1:
          option.items.push({
            name: 'NOP',
            range: `${optionOffset}:${optionOffset + 1}`
          });
          optionOffset++;
          break;

        case 2:
          optionItems.push('Maximum segment size');
          option.items.push({
            name: 'Maximum segment size',
            value: parentLayer.payload.readUInt16BE(optionOffset + 2),
            range: `${optionOffset}:${optionOffset + 4}`
          });
          optionOffset += 4;
          break;

        case 3:
          optionItems.push('Window scale');
          option.items.push({
            name: 'Window scale',
            value: parentLayer.payload.readUInt8(optionOffset + 2),
            range: `${optionOffset}:${optionOffset + 3}`
          });
          optionOffset += 3;
          break;

        case 4:
          optionItems.push('Selective ACK permitted');
          option.items.push({
            name: 'Selective ACK permitted',
            range: `${optionOffset}:${optionOffset + 2}`
          });
          optionOffset += 2;
          break;

        // TODO: https://tools.ietf.org/html/rfc2018
        case 5:
          let length = parentLayer.payload.readUInt8(optionOffset + 1);
          optionItems.push('Selective ACK');
          option.items.push({
            name: 'Selective ACK',
            value: parentLayer.payload.slice(optionOffset + 2, optionOffset + length),
            data: `${optionOffset}:${optionOffset + length}`
          });

          optionOffset += length;
          break;

        case 8:
          let mt = parentLayer.payload.readUInt32BE(optionOffset + 2);
          let et = parentLayer.payload.readUInt32BE(optionOffset + 2);
          optionItems.push('Timestamps');
          option.items.push({
            name: 'Timestamps',
            value: `${mt} - ${et}`,
            range: `${optionOffset}:${optionOffset + 10}`,
            items: [{
              name: 'My timestamp',
              value: mt,
              range: `${optionOffset + 2}:${optionOffset + 6}`
            }, {
              name: 'Echo reply timestamp',
              value: et,
              range: `${optionOffset + 6}:${optionOffset + 10}`
            }]
          });
          optionOffset += 10;
          break;

        default:
          throw new Error('unknown option');
      }
    }

    option.value = optionItems.join(',');
    layer.items.push(option);

    layer.range = optionDataOffset + ':';
    layer.payload = parentLayer.payload.slice(optionDataOffset);
    layer.items.push({
      name: 'Payload',
      id: 'payload',
      range: optionDataOffset + ':',
      value: layer.payload
    });

    layer.summary = `${src.data} -> ${dst.data} seq:${seq} ack:${ack}`;

    let id = src.data + '/' + dst.data;
    let chunk = {
      namespace: parentLayer.namespace,
      id: id,
      layer: layer,
      attrs: {
        payload: layer.payload,
        seq: seq
      }
    };

    if (flags.get('ACK') && flags.get('FIN')) {
      chunk.end = true;
    }

    return [new Layer(layer), new StreamChunk(chunk)];
  }
};
