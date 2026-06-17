/**
 * Flag loader — reads flags.json from flag-data volume and
 * distributes values to /app/flags/*.txt files.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const FLAG_DATA_PATH = '/flag-data/flags.json';
const FLAGS_DIR = '/app/flags';

let flags = {};

async function loadFlags() {
  try {
    if (!fs.existsSync(FLAG_DATA_PATH)) {
      console.warn('[flags] flags.json not found at', FLAG_DATA_PATH);
      return;
    }

    const raw = fs.readFileSync(FLAG_DATA_PATH, 'utf8');
    flags = JSON.parse(raw);

    // Write individual flag files for challenges that use file reads
    fs.mkdirSync(FLAGS_DIR, { recursive: true });

    const fileFlags = {
      'inj03.txt': flags.inj03,
      'inj04.txt': flags.inj04,
      'bac04.txt': flags.bac04,
      'ss02.txt':  flags.ss02,
      'ss03.txt':  flags.ss03,
    };

    for (const [filename, value] of Object.entries(fileFlags)) {
      if (value) {
        fs.writeFileSync(path.join(FLAGS_DIR, filename), value, 'utf8');
      }
    }

    console.log(`[flags] Loaded ${Object.keys(flags).length} flags`);
  } catch (err) {
    console.error('[flags] Error loading flags:', err.message);
  }
}

function getFlag(code) {
  return flags[code] || null;
}

function getAllFlags() {
  return { ...flags };
}

module.exports = { loadFlags, getFlag, getAllFlags };
