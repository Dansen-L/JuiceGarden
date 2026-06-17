/**
 * Redis client and session store configuration
 */
'use strict';

const { createClient } = require('redis');
// connect-redis v7 ships RedisStore as the default export only (exports.default).
// Named-export destructuring yields undefined; use .default explicitly.
const RedisStore = require('connect-redis').default;

const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://redis:6379',
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 100, 3000)
  }
});

redisClient.on('error', (err) => console.error('[redis] Client error:', err));
redisClient.on('connect', () => console.log('[redis] Connected'));

// Connect immediately (non-blocking — session store tolerates late connect)
redisClient.connect().catch(console.error);

module.exports = { redisClient, RedisStore };
