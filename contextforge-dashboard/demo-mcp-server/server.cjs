// Minimal dependency-free MCP server (Streamable HTTP, JSON responses).
// Run: node server.js   -> listens on http://127.0.0.1:9100/mcp
const http = require('http');

const PORT = process.env.PORT || 9100;

const tools = [
  {
    name: 'echo',
    description: 'Echo back the provided message.',
    inputSchema: {
      type: 'object',
      properties: { message: { type: 'string', description: 'Text to echo' } },
      required: ['message'],
    },
    run: (a) => String(a.message),
  },
  {
    name: 'add',
    description: 'Add two numbers.',
    inputSchema: {
      type: 'object',
      properties: { a: { type: 'number' }, b: { type: 'number' } },
      required: ['a', 'b'],
    },
    run: (a) => String(Number(a.a) + Number(a.b)),
  },
  {
    name: 'get_time',
    description: 'Return the current server time (ISO 8601).',
    inputSchema: { type: 'object', properties: {} },
    run: () => new Date().toISOString(),
  },
  {
    name: 'reverse_text',
    description: 'Reverse a string.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string' } },
      required: ['text'],
    },
    run: (a) => String(a.text).split('').reverse().join(''),
  },
];

function handle(msg) {
  const { id, method, params } = msg;
  const ok = (result) => ({ jsonrpc: '2.0', id, result });
  const err = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'initialize':
      return ok({
        protocolVersion: (params && params.protocolVersion) || '2025-03-26',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'demo-mcp-server', version: '1.0.0' },
      });
    case 'ping':
      return ok({});
    case 'tools/list':
      return ok({ tools: tools.map(({ run, ...t }) => t) });
    case 'tools/call': {
      const t = tools.find((x) => x.name === params.name);
      if (!t) return err(-32602, `Unknown tool: ${params.name}`);
      try {
        return ok({ content: [{ type: 'text', text: t.run(params.arguments || {}) }], isError: false });
      } catch (e) {
        return ok({ content: [{ type: 'text', text: String(e) }], isError: true });
      }
    }
    case 'resources/list':
      return ok({ resources: [] });
    case 'prompts/list':
      return ok({ prompts: [] });
    default:
      return err(-32601, `Method not found: ${method}`);
  }
}

http
  .createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end('{"status":"ok"}');
    }
    if (req.url !== '/mcp') {
      res.writeHead(404);
      return res.end();
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' });
      return res.end();
    }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      let msg;
      try {
        msg = JSON.parse(body);
      } catch {
        res.writeHead(400);
        return res.end();
      }
      const send = (obj, status = 200) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(obj));
      };
      if (Array.isArray(msg)) {
        const out = msg.filter((m) => m.id !== undefined).map(handle);
        return out.length ? send(out) : (res.writeHead(202), res.end());
      }
      if (msg.id === undefined) {
        res.writeHead(202); // notification
        return res.end();
      }
      send(handle(msg));
    });
  })
  .listen(PORT, '127.0.0.1', () => console.log(`demo MCP server on http://127.0.0.1:${PORT}/mcp`));
