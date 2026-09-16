import type { AppConfig } from './config.js';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;

export interface Logger {
  debug(msg: string, meta?: unknown): void;
  info(msg: string, meta?: unknown): void;
  warn(msg: string, meta?: unknown): void;
  error(msg: string, meta?: unknown): void;
}

export function createLogger(level: AppConfig['logLevel'] = 'info', sink: (line: string) => void = (l) => console.log(l)): Logger {
  const min = LEVELS[level];
  const emit = (lvl: keyof typeof LEVELS, msg: string, meta?: unknown) => {
    if (LEVELS[lvl] < min) return;
    const line = JSON.stringify({ t: new Date().toISOString(), lvl, msg, ...(meta === undefined ? {} : { meta }) });
    sink(line);
  };
  return {
    debug: (m, meta) => emit('debug', m, meta),
    info: (m, meta) => emit('info', m, meta),
    warn: (m, meta) => emit('warn', m, meta),
    error: (m, meta) => emit('error', m, meta),
  };
}

export const silentLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
