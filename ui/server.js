const { createServer } = require('node:http');
const fs = require('node:fs');

// (async () => {
//   console.log("server.js is running");
  // watch('./web/index.html', { persistent: true, throwIfNoEntry: true }, (eventType, filename) => {
  //   console.log(`File ${filename} has been ${eventType}`);
  //   if (eventType === 'change') {
  //     console.log('Reloading the page...');
  //   }
  // });

//   watchFile('./web/index.html', { persistent: true, interval: 1000 }, (curr, prev) => {
//     console.log(`File index.html has been changed. Previous mtime: ${prev.mtime}, Current mtime: ${curr.mtime}`);
//   });
// })();

async function bootstrap() {
  const TARGET_FILE = './sample.json';

  if (!fs.existsSync(TARGET_FILE)) {
    throw new Error(`File ${TARGET_FILE} does not exist.`);
  }

const server = createServer((req, res) => {
  console.log(`Received request for ${req.url}`);
  if (req.url === '/sse') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Catche-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    res.write('data: Connected to the SSE server\n\n');

    let lastReadPosition = fs.statSync(TARGET_FILE).size;

      console.log(`Watch for changes on: ${TARGET_FILE}`);
      console.log(`Initial file size: ${lastReadPosition} bytes`);

    fs.watchFile(TARGET_FILE, { persistent: true, interval: 1000 }, (curr, prev) => {
      if (curr.mtime !== prev.mtime) {
        // const diff = fs.readFileSync(TARGET_FILE, 'utf8');
        // res.write('data: reload\n\n');
        fs.stat(TARGET_FILE, (err, stats) => {
            if (err) return console.log(err);

          if (stats.size < lastReadPosition) {
              console.log('File truncated. Resetting pointer. ');
              lastReadPosition = 0;
            }

            const newBytesCount = stats.size - lastReadPosition;
            if (newBytesCount <= 0) return;
          fs.open(TARGET_FILE, 'r', (err, fd) => {
              if (err) return console.log(err);

            const buffer = Buffer.alloc(newBytesCount);

              fs.read(fd, buffer, 0, newBytesCount, lastReadPosition, (err, bytesRead) => {
                if (err) {
                  fs.close(fd, () => {});
                  return console.log(err);
                }

                const newContent = buffer.toString('utf8', 0, bytesRead);
                console.log(`[New Change]: ${newContent.trim()}`);
                res.write(`data: ${newContent.trim()}\n\n`);

                lastReadPosition += bytesRead;

                fs.close(fd, () => {});
              });
            })
          });
      }
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
  }
});

server.listen(3000, () => console.log('Server is running on http://localhost:3000'));
}

bootstrap().catch((err) => console.error(err));
