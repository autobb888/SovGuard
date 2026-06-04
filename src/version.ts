import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// ESM-safe: __dirname is undefined under "type": "module", which crashed the
// built self-hosted server on boot (node dist/server.js).
const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
export const version: string = pkg.version;
