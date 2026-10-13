// WebRTC signaling and binary packet bridge for browser/WASM clients.
// The app must supply a WASM-backed protocol engine via onPacket().
// File cryptography, manifest verification and RLNC decoding are NOT done here.
export class BadsharingBrowserPeer {
  constructor({ baseURL, room, peerID, token, iceServers = [], onPacket, onPeer }) {
    if (!baseURL || !room || !peerID || !token || token.length < 32) throw new Error("Invalid signaling configuration");
    if (new URL(baseURL).protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(new URL(baseURL).hostname)) {
      throw new Error("HTTPS required for remote signaling");
    }
    this.baseURL = baseURL;
    this.room = room;
    this.peerID = peerID;
    this.token = token;
    this.iceServers = iceServers;
    this.onPacket = onPacket ?? (() => {});
    this.onPeer = onPeer ?? (() => {});
    this.peers = new Map();
    this.stopped = false;
  }
  async #request(path, method = "GET", data) {
    const endpoint = new URL(path, this.baseURL);
    endpoint.searchParams.set("room", this.room);
    endpoint.searchParams.set("peer", this.peerID);
    const response = await fetch(endpoint, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: data ? JSON.stringify(data) : undefined,
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`Signaling HTTP ${response.status}`);
    return method === "POST" ? null : response.json();
  }
  #newPeer(id, initiator) {
    if (this.peers.has(id)) return this.peers.get(id);
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    const peer = { pc, control: null, data: null, ready: false };
    this.peers.set(id, peer);
    const attach = channel => {
      if (!["badsharing-control", "badsharing-rlnc"].includes(channel.label)) {
        channel.close(); return;
      }
      channel.binaryType = "arraybuffer";
      if (channel.label === "badsharing-control") peer.control = channel;
      else peer.data = channel;
      channel.addEventListener("message", async event => {
        const packet = event.data instanceof ArrayBuffer ? new Uint8Array(event.data)
          : new Uint8Array(await event.data.arrayBuffer());
        this.onPacket(id, packet);
      });
      channel.addEventListener("open", () => {
        if (peer.control?.readyState === "open" && peer.data?.readyState === "open" && !peer.ready) {
          peer.ready = true; this.onPeer(id);
        }
      });
    };
    pc.addEventListener("datachannel", e => attach(e.channel));
    pc.addEventListener("connectionstatechange", () => {
      if (["failed", "closed"].includes(pc.connectionState)) {
        this.peers.delete(id);
        pc.close();
      }
    });
    if (initiator) {
      attach(pc.createDataChannel("badsharing-control"));
      attach(pc.createDataChannel("badsharing-rlnc", { ordered: false, maxRetransmits: 0 }));
    }
    return peer;
  }
  async #gather(pc) {
    if (pc.iceGatheringState === "complete") return;
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => { pc.removeEventListener("icegatheringstatechange", changed); reject(new Error("ICE gathering timed out")); }, 25000);
      const changed = () => {
        if (pc.iceGatheringState === "complete") {
          clearTimeout(deadline); pc.removeEventListener("icegatheringstatechange", changed); resolve();
        }
      };
      pc.addEventListener("icegatheringstatechange", changed);
      changed();
    });
  }
  async #send(target, type, data) {
    await this.#request("/v1/signal", "POST", { from: this.peerID, to: target, type, data });
  }
  async #process(message) {
    if (message.to !== this.peerID) return;
    if (message.type === "offer") {
      if (message.from >= this.peerID || this.peers.has(message.from)) return;
      const peer = this.#newPeer(message.from, false);
      await peer.pc.setRemoteDescription({ type: "offer", sdp: message.data });
      const answer = await peer.pc.createAnswer();
      await peer.pc.setLocalDescription(answer);
      await this.#gather(peer.pc);
      await this.#send(message.from, "answer", peer.pc.localDescription.sdp);
    } else if (message.type === "answer") {
      const peer = this.peers.get(message.from);
      if (peer) await peer.pc.setRemoteDescription({ type: "answer", sdp: message.data });
    }
  }
  async start(signal) {
    this.stopped = false;
    while (!this.stopped && !signal?.aborted) {
      // Poll both discovery and incoming signaling without storing file data.
      const [members, messages] = await Promise.all([
        this.#request("/v1/peers"), this.#request("/v1/signal"),
      ]);
      for (const id of members) {
        if (id <= this.peerID || this.peers.has(id) || this.peers.size >= 32) continue;
        const peer = this.#newPeer(id, true);
        const offer = await peer.pc.createOffer();
        await peer.pc.setLocalDescription(offer);
        await this.#gather(peer.pc);
        await this.#send(id, "offer", peer.pc.localDescription.sdp);
      }
      for (const message of messages) {
        try { await this.#process(message); } catch (error) { console.error("WebRTC signaling:", error); }
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
  async send(peerID, packet) {
    const peer = this.peers.get(peerID);
    const isShard = packet[0] === 66 && packet[1] === 83 && packet[2] === 87 && packet[3] === 49 && packet[4] === 2;
    const channel = isShard ? peer?.data : peer?.control;
    if (!channel || channel.readyState !== "open") throw new Error("Peer not connected");
    if (packet.length > 8192) throw new Error("Oversized packet");
    while (channel.bufferedAmount >= 2 * 1024 * 1024) {
      await new Promise(resolve => setTimeout(resolve, 10));
      if (channel.readyState !== "open") throw new Error("Peer disconnected");
    }
    channel.send(packet);
  }
  stop() {
    this.stopped = true;
    for (const peer of this.peers.values()) peer.pc.close();
    this.peers.clear();
  }
}
