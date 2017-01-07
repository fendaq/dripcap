<packet-view>

<div>
  <ul if={ packet }>
    <li>
      <i class="fa fa-circle-o"></i>
      <a class="text-label">Timestamp:</a><i>{ packet.timestamp }</i>
    </li>
    <li>
      <i class="fa fa-circle-o"></i>
      <a class="text-label">Captured Length:</a><i>{ packet.payload.length }</i>
    </li>
    <li>
      <i class="fa fa-circle-o"></i>
      <a class="text-label">Actual Length:</a><i>{ packet.length }</i>
    </li>
    <li if={ packet.caplen < packet.length }>
      <i class="fa fa-exclamation-circle text-warn"> This packet has been truncated.</i>
    </li>
  </ul>
  <packet-view-layer if={ packet } each={ layer, ns in rootLayers } layer={ layer }></packet-view-layer>
</div>

<script>
  const { remote } = require('electron');
  const { PubSub } = require('dripcap');

  this.on('mount', () => {
    PubSub.sub(this, 'packet-list-view:select', (pkt) => {
      this.packet = pkt;
      if (pkt != null) {
        this.rootLayers = this.packet.layers;
      }
      this.update();
    });
  });

  this.on('unmount', () => {
    PubSub.removeHolder(this);
  });
</script>

<style type="text/less">
  :scope {
    -webkit-user-select: auto;
    table {
      width: 100%;
      align-self: stretch;
      border-spacing: 0;
      padding: 10px;
      td {
        cursor: default;
      }
    }
    .text-label {
      cursor: default;
      color: var(--color-keywords);
    }
    .layer-name {
      white-space: nowrap;
      cursor: default;
      margin-left: 10px;
    }
    .text-summary {
      padding: 0 10px;
    }
    ul {
      padding-left: 20px;
    }
    li {
      white-space: nowrap;
      list-style: none;
    }
    i {
      font-style: normal;
    }
    i.base {
      font-weight: bold;
    }
    .label {
      margin: 0;
    }
    .fa-circle-o {
      opacity: 0.5;
    }
  }
</style>

</packet-view>
