import { serve } from '@hono/node-server';
import { getConnInfo } from '@hono/node-server/conninfo';
import { loadConfigFromEnv } from './config.js';
import { createLogger } from './logger.js';
import { loadMetadataStore } from './policy/mds.js';
import { createApp } from './app.js';

async function main() {
  const config = loadConfigFromEnv();
  const log = createLogger(config.logLevel);
  log.info('starting', { rpId: config.rpId, origin: config.origin, port: config.port, dbPath: config.dbPath, policy: config.policy.version });
  const mds = await loadMetadataStore(config.mds, log);
  const { app } = createApp({ config, log, mds });

  // Attach the socket address so rate limiting works without a proxy.
  serve(
    {
      fetch: (req, env) => {
        const headers = new Headers(req.headers);
        headers.delete('x-hv-conn-ip'); // never trust a client-supplied value
        try {
          const info = getConnInfo({ env } as never);
          if (info?.remote?.address) headers.set('x-hv-conn-ip', info.remote.address);
        } catch {
          /* ignore */
        }
        return app.fetch(new Request(req, { headers }), env);
      },
      port: config.port,
      hostname: process.env.HV_HOST ?? '0.0.0.0',
    },
    (info) => log.info('listening', { address: info.address, port: info.port, demo: `${config.origin}/demo/`, diagnostics: `${config.origin}/diagnostics` }),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
