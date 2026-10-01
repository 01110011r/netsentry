const { createServer } = require('node:http');
const fs = require('node:fs');

// const TARGET_FILE = './sample.json';
const TARGET_FILE = '/tmp/netsentry_report.json';
const PORT = 3000;

if (!fs.existsSync(TARGET_FILE)) {
  throw new Error(`File ${TARGET_FILE} does not exist.`);
}

function readAllEvents() {
  const raw = fs.readFileSync(TARGET_FILE, 'utf8');
  return raw.split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

const server = createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    fs.readFile('./web/index.html', (err, data) => {
      if (err) { res.writeHead(500); return res.end('Internal Server Error'); }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  if (req.url === '/sse') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // 1. Send everything that already happened, as ONE named event,
    //    so a freshly opened tab isn't empty.
    res.write(`event: backlog\ndata: ${JSON.stringify(readAllEvents())}\n\n`);

    let lastReadPosition = fs.statSync(TARGET_FILE).size;

    const onChange = (curr, prev) => {
      if (curr.mtime === prev.mtime) return;

      fs.stat(TARGET_FILE, (err, stats) => {
        if (err) return console.error(err);
        if (stats.size < lastReadPosition) lastReadPosition = 0; // file was truncated/rotated

        const newBytes = stats.size - lastReadPosition;
        if (newBytes <= 0) return;

        fs.open(TARGET_FILE, 'r', (err, fd) => {
          if (err) return console.error(err);
          const buffer = Buffer.alloc(newBytes);
          fs.read(fd, buffer, 0, newBytes, lastReadPosition, (err, bytesRead) => {
            fs.close(fd, () => {});
            if (err) return console.error(err);

            lastReadPosition += bytesRead;

            // 2. Send each new JSON line as its OWN "append" event -
            //    never bundle multiple lines into one `data:` field.
            buffer.toString('utf8', 0, bytesRead)
              .split('\n')
              .map(l => l.trim())
              .filter(Boolean)
              .forEach(line => {
                res.write(`event: append\ndata: ${line}\n\n`);
              });
          });
        });
      });
    };

    fs.watchFile(TARGET_FILE, { persistent: true, interval: 1000 }, onChange);

    // 3. Stop watching when this client disconnects - otherwise every
    //    page reload during development leaks another watcher forever.
    req.on('close', () => {
      fs.unwatchFile(TARGET_FILE, onChange);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('404 Not Found');
});

server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
