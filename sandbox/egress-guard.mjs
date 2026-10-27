// Preloaded into every sandboxed MCP server (node --import). Blocks network connections to
// hosts outside AGENTGATE_EGRESS_ALLOW. Node's permission model already denies child
// processes, workers, native addons and raw bindings (process.binding), so every TCP/TLS
// connection must go through net.Socket.prototype.connect, which is patched and frozen here.
import net from "node:net";
import dgram from "node:dgram";

const allow = new Set(
  (process.env.AGENTGATE_EGRESS_ALLOW ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
);
delete process.env.AGENTGATE_EGRESS_ALLOW;

function hostOf(args) {
  const a = args[0];
  if (Array.isArray(a)) return hostOf(a);
  if (a && typeof a === "object") return a.path ? `unix:${a.path}` : (a.host ?? "localhost");
  if (typeof a === "string" && isNaN(Number(a))) return `unix:${a}`;
  return typeof args[1] === "string" ? args[1] : "localhost";
}

const realConnect = net.Socket.prototype.connect;
function guardedConnect(...args) {
  const host = String(hostOf(args)).toLowerCase();
  if (!allow.has(host)) {
    const err = new Error(`AgentGate sandbox: network egress to ${host} is not allowed`);
    err.code = "EGRESS_DENIED";
    process.nextTick(() => this.destroy(err));
    return this;
  }
  return realConnect.apply(this, args);
}
Object.defineProperty(net.Socket.prototype, "connect", { value: guardedConnect, writable: false, configurable: false });

const deny = () => {
  throw Object.assign(new Error("AgentGate sandbox: UDP is not allowed"), { code: "EGRESS_DENIED" });
};
for (const m of ["send", "bind", "connect"]) {
  Object.defineProperty(dgram.Socket.prototype, m, { value: deny, writable: false, configurable: false });
}
