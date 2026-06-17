/**
 * Sequelize ORM setup and model registration.
 */
'use strict';

const { Sequelize, DataTypes, QueryTypes } = require('sequelize');
const path = require('path');

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  pool: { max: 10, min: 0, acquire: 30000, idle: 10000 }
});

// ──────────────────────────────────────────────
// Models
// ──────────────────────────────────────────────

const User = sequelize.define('User', {
  id: { type: DataTypes.STRING(36), primaryKey: true },  // UUID v1 string
  username: { type: DataTypes.TEXT, unique: true, allowNull: false },
  display_name: { type: DataTypes.TEXT },
  bio: { type: DataTypes.TEXT },
  email: { type: DataTypes.TEXT, unique: true, allowNull: false },
  password_hash: { type: DataTypes.TEXT, allowNull: false },
  role: { type: DataTypes.ENUM('guest', 'customer', 'staff', 'manager', 'admin'), defaultValue: 'customer' },
  loyalty_points: { type: DataTypes.INTEGER, defaultValue: 0 },
  reset_token: { type: DataTypes.TEXT },
  reset_token_expires: { type: DataTypes.DATE },
  profile_json: { type: DataTypes.JSONB, defaultValue: {} },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
  tableName: 'users',
  timestamps: false
});

const Product = sequelize.define('Product', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.TEXT, allowNull: false },
  description: { type: DataTypes.TEXT },
  price_cents: { type: DataTypes.INTEGER, allowNull: false },
  stock: { type: DataTypes.INTEGER, defaultValue: 100 },
  category: { type: DataTypes.TEXT },
  image_path: { type: DataTypes.TEXT },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true }
}, {
  tableName: 'products',
  timestamps: false
});

const Order = sequelize.define('Order', {
  id: { type: DataTypes.STRING(36), primaryKey: true },  // UUID v1
  user_id: { type: DataTypes.STRING(36), allowNull: false },
  status: {
    type: DataTypes.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'refunded'),
    defaultValue: 'pending'
  },
  items_json: { type: DataTypes.JSONB, allowNull: false },
  total_price_cents: { type: DataTypes.INTEGER, defaultValue: 0 },
  coupon_code: { type: DataTypes.TEXT },
  coupon_discount: { type: DataTypes.INTEGER, defaultValue: 0 },
  internal_notes: { type: DataTypes.TEXT },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  updated_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
  tableName: 'orders',
  timestamps: false
});

const Coupon = sequelize.define('Coupon', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  code: { type: DataTypes.TEXT, unique: true, allowNull: false },
  discount_type: { type: DataTypes.ENUM('percent', 'fixed'), allowNull: false },
  discount_value: { type: DataTypes.INTEGER, allowNull: false },
  uses_remaining: { type: DataTypes.INTEGER, defaultValue: 1 },
  single_use: { type: DataTypes.BOOLEAN, defaultValue: true },
  expires_at: { type: DataTypes.DATE }
}, {
  tableName: 'coupons',
  timestamps: false
});

const Review = sequelize.define('Review', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  user_id: { type: DataTypes.STRING(36), allowNull: false },
  product_id: { type: DataTypes.INTEGER, allowNull: false },
  content: { type: DataTypes.TEXT, allowNull: false },
  rating: { type: DataTypes.INTEGER, defaultValue: 5 },
  approved: { type: DataTypes.BOOLEAN, defaultValue: false },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
  tableName: 'reviews',
  timestamps: false
});

const Secret = sequelize.define('Secret', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  key: { type: DataTypes.TEXT, unique: true, allowNull: false },
  value: { type: DataTypes.TEXT, allowNull: false }
}, {
  tableName: 'secrets',
  timestamps: false
});

const Webhook = sequelize.define('Webhook', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  user_id: { type: DataTypes.STRING(36), allowNull: false },
  url: { type: DataTypes.TEXT, allowNull: false },
  event_type: { type: DataTypes.TEXT, defaultValue: 'order.created' },
  active: { type: DataTypes.BOOLEAN, defaultValue: true },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
  tableName: 'webhooks',
  timestamps: false
});

const AuditLog = sequelize.define('AuditLog', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  actor_id: { type: DataTypes.STRING(36) },
  action: { type: DataTypes.TEXT, allowNull: false },
  target_type: { type: DataTypes.TEXT },
  target_id: { type: DataTypes.TEXT },
  details_json: { type: DataTypes.JSONB, defaultValue: {} },
  ip_address: { type: DataTypes.TEXT },
  timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
  tableName: 'audit_log',
  timestamps: false
});

// ──────────────────────────────────────────────
// Database initialization and seed
// ──────────────────────────────────────────────
async function initDb() {
  await sequelize.authenticate();
  console.log('[db] Connected to PostgreSQL');

  // Create tables
  await sequelize.sync({ alter: false, force: false });

  // Check if already seeded
  const userCount = await User.count();
  if (userCount === 0) {
    await seedDatabase();
  } else {
    console.log('[db] Database already seeded, skipping');
    // Still update secrets with current flags
    await updateFlagSecrets();
    // Restore bot accounts to seed defaults (clears CS-03/BAC-02 state on soft reset)
    await restoreBotDefaults();
  }
}

async function updateFlagSecrets() {
  const { getFlag } = require('../utils/flags');
  const flagKeys = ['inj01', 'inj02', 'ss01'];
  for (const key of flagKeys) {
    const val = getFlag(key);
    if (val) {
      await Secret.upsert({ key, value: val });
    }
  }
}

/**
 * Restore bot accounts to their seed defaults on every non-first startup.
 * This clears CS-03 state (admin_bot email change) and BAC-02 state (role changes).
 * Called during soft reset (services restarted, DB preserved).
 */
async function restoreBotDefaults() {
  try {
    const bcrypt = require('bcryptjs');
    const botDefaults = [
      {
        username: 'admin_bot',
        email: process.env.ADMIN_BOT_EMAIL || 'admin.bot@garden.lab',
        role: 'admin'
      },
      {
        username: 'manager_bot',
        email: process.env.MANAGER_BOT_EMAIL || 'manager.bot@garden.lab',
        role: 'manager'
      },
      {
        username: 'staff_bot',
        email: process.env.STAFF_BOT_EMAIL || 'staff.bot@garden.lab',
        role: 'staff'
      }
    ];
    for (const bot of botDefaults) {
      await User.update(
        { email: bot.email, role: bot.role },
        { where: { username: bot.username } }
      );
    }
    console.log('[db] Bot accounts restored to seed defaults (CS-03/BAC-02 state cleared)');
  } catch (err) {
    console.warn('[db] Could not restore bot defaults:', err.message);
  }
}

async function seedDatabase() {
  console.log('[db] Seeding database...');
  const bcrypt = require('bcryptjs');
  const { mintUuidV1 } = require('../utils/uuid_v1');
  const { getFlag } = require('../utils/flags');

  // Seed users (bot accounts + regular users)
  const now = Date.now();
  const passwordHash = async (pwd) => bcrypt.hash(pwd, 8);

  const botUsers = [
    {
      id: mintUuidV1(now - 10000),
      username: 'staff_bot',
      display_name: 'Staff Bot',
      email: process.env.STAFF_BOT_EMAIL || 'staff.bot@garden.lab',
      password_hash: await passwordHash(process.env.STAFF_BOT_PASSWORD || 'StaffBot2024!'),
      role: 'staff',
      created_at: new Date(now - 10000)
    },
    {
      id: mintUuidV1(now - 9000),
      username: 'manager_bot',
      display_name: 'Manager Bot',
      email: process.env.MANAGER_BOT_EMAIL || 'manager.bot@garden.lab',
      password_hash: await passwordHash(process.env.MANAGER_BOT_PASSWORD || 'ManagerBot2024!'),
      role: 'manager',
      created_at: new Date(now - 9000)
    },
    {
      id: mintUuidV1(now - 8000),
      username: 'admin_bot',
      display_name: 'Admin Bot',
      email: process.env.ADMIN_BOT_EMAIL || 'admin.bot@garden.lab',
      password_hash: await passwordHash(process.env.ADMIN_BOT_PASSWORD || 'AdminBot2024!'),
      role: 'admin',
      created_at: new Date(now - 8000)
    }
  ];

  const regularUsers = [
    {
      id: mintUuidV1(now - 7000),
      username: 'alice',
      display_name: 'Alice Green',
      email: 'alice@example.com',
      password_hash: await passwordHash('alice123'),
      role: 'customer',
      created_at: new Date(now - 7000)
    },
    {
      id: mintUuidV1(now - 6000),
      username: 'bob',
      display_name: 'Bob Smith',
      email: 'bob@example.com',
      password_hash: await passwordHash('bob123'),
      role: 'customer',
      created_at: new Date(now - 6000)
    }
  ];

  const allUsers = [...botUsers, ...regularUsers];
  for (const u of allUsers) {
    await User.upsert(u);
  }

  // Seed products (10 items)
  const products = [
    { name: 'Green Garden Juice', description: 'Refreshing blend of spinach, cucumber, and apple', price_cents: 850, category: 'juice', image_path: '/static/img/green-garden.jpg' },
    { name: 'Tropical Sunrise', description: 'Mango, pineapple, and passion fruit blend', price_cents: 950, category: 'juice', image_path: '/static/img/tropical-sunrise.jpg' },
    { name: 'Beet Power Boost', description: 'Beetroot, carrot, and ginger fusion', price_cents: 750, category: 'juice', image_path: '/static/img/beet-power.jpg' },
    { name: 'Citrus Cleanse', description: 'Orange, lemon, and turmeric detox blend', price_cents: 700, category: 'juice', image_path: '/static/img/citrus-cleanse.jpg' },
    { name: 'Berry Blast Smoothie', description: 'Mixed berries with coconut milk', price_cents: 1050, category: 'smoothie', image_path: '/static/img/berry-blast.jpg' },
    { name: 'Avocado Dream', description: 'Avocado, banana, and almond milk smoothie', price_cents: 1200, category: 'smoothie', image_path: '/static/img/avocado-dream.jpg' },
    { name: 'Immunity Shot Pack', description: 'Daily immunity shots: ginger, turmeric, cayenne (5-pack)', price_cents: 1500, category: 'shots', image_path: '/static/img/immunity-shots.jpg' },
    { name: 'Cold Brew Matcha', description: 'Japanese ceremonial matcha cold brew', price_cents: 650, category: 'tea', image_path: '/static/img/matcha.jpg' },
    { name: 'Watermelon Mint Cooler', description: 'Fresh watermelon with mint and lime', price_cents: 800, category: 'juice', image_path: '/static/img/watermelon-mint.jpg' },
    { name: 'Protein Garden Bowl', description: 'Açaí bowl with protein powder, granola, and seasonal fruit', price_cents: 1350, category: 'bowl', image_path: '/static/img/protein-bowl.jpg' },
  ];

  for (const p of products) {
    await Product.upsert({ ...p, id: products.indexOf(p) + 1, is_active: true });
  }

  // Reset the products sequence so Product.create() (without explicit id) gets the
  // next available id after the seeded rows (1–10), avoiding a UNIQUE violation.
  await sequelize.query(
    "SELECT setval(pg_get_serial_sequence('products', 'id'), (SELECT MAX(id) FROM products))"
  );

  // Seed coupons
  const coupons = [
    { code: 'WELCOME10', discount_type: 'percent', discount_value: 10, uses_remaining: 100, single_use: false, expires_at: new Date('2027-12-31') },
    { code: 'SAVE5', discount_type: 'fixed', discount_value: 500, uses_remaining: 50, single_use: false, expires_at: new Date('2027-12-31') },
    { code: 'FREESHIP', discount_type: 'fixed', discount_value: 200, uses_remaining: 1, single_use: true, expires_at: new Date('2027-12-31') },  // BL-02 race target
    { code: 'VIP20', discount_type: 'percent', discount_value: 20, uses_remaining: 5, single_use: false, expires_at: new Date('2027-12-31') },
    { code: 'FIRST50', discount_type: 'percent', discount_value: 50, uses_remaining: 1, single_use: true, expires_at: new Date('2027-12-31') },
  ];

  for (let i = 0; i < coupons.length; i++) {
    await Coupon.upsert({ ...coupons[i], id: i + 1 });
  }

  // Seed orders
  // BAC-01: Admin target order (status=confirmed, excluded from /recent)
  //         Reference order: Staff order (status=delivered, included in /recent)
  // Use historical timestamps for UUID-embedded timestamp matching
  const adminUser = botUsers.find(u => u.username === 'admin_bot');
  const staffUser = botUsers.find(u => u.username === 'staff_bot');

  // Reference order timestamp (appears in /api/orders/recent)
  const refTs = now - 100000;  // ~100s ago
  // Target order timestamp: within ±1s of reference (for BAC-01 enumeration)
  const targetTs = refTs - 500;  // 0.5s before reference

  const bac01Flag = getFlag('bac01') || 'JG{placeholder_bac01}';

  const refOrderId = mintUuidV1(refTs);
  const targetOrderId = mintUuidV1(targetTs);

  await Order.upsert({
    id: refOrderId,
    user_id: staffUser.id,
    status: 'delivered',
    items_json: [{ product_id: 1, quantity: 2, price_cents: 850 }],
    total_price_cents: 1700,
    created_at: new Date(refTs),
    updated_at: new Date(refTs)
  });

  await Order.upsert({
    id: targetOrderId,
    user_id: adminUser.id,
    status: 'confirmed',  // excluded from /recent
    items_json: [{ product_id: 1, quantity: 1, price_cents: 850, flag: bac01Flag }],
    total_price_cents: 850,
    created_at: new Date(targetTs),
    updated_at: new Date(targetTs)
  });

  // Seed additional sample orders (20+ total) for realistic dataset
  const aliceUser = regularUsers.find(u => u.username === 'alice');
  const bobUser = regularUsers.find(u => u.username === 'bob');
  const managerUser = botUsers.find(u => u.username === 'manager_bot');

  const sampleOrderData = [
    // Alice's delivered orders
    { userIdx: aliceUser.id, status: 'delivered', items: [{ product_id: 1, quantity: 2, price_cents: 850 }], total: 1700, ago: 200000 },
    { userIdx: aliceUser.id, status: 'delivered', items: [{ product_id: 5, quantity: 1, price_cents: 1050 }], total: 1050, ago: 350000 },
    { userIdx: aliceUser.id, status: 'delivered', items: [{ product_id: 2, quantity: 2, price_cents: 950 }], total: 1900, ago: 500000 },
    { userIdx: aliceUser.id, status: 'delivered', items: [{ product_id: 7, quantity: 1, price_cents: 1500 }], total: 1500, ago: 650000 },
    { userIdx: aliceUser.id, status: 'delivered', items: [{ product_id: 8, quantity: 3, price_cents: 650 }], total: 1950, ago: 800000 },
    // Bob's orders
    { userIdx: bobUser.id, status: 'delivered', items: [{ product_id: 3, quantity: 1, price_cents: 750 }], total: 750, ago: 250000 },
    { userIdx: bobUser.id, status: 'delivered', items: [{ product_id: 4, quantity: 2, price_cents: 700 }], total: 1400, ago: 400000 },
    { userIdx: bobUser.id, status: 'delivered', items: [{ product_id: 6, quantity: 1, price_cents: 1200 }], total: 1200, ago: 550000 },
    { userIdx: bobUser.id, status: 'shipped',   items: [{ product_id: 9, quantity: 2, price_cents: 800 }], total: 1600, ago: 120000 },
    { userIdx: bobUser.id, status: 'confirmed', items: [{ product_id: 10, quantity: 1, price_cents: 1350 }], total: 1350, ago: 60000 },
    // Manager bot orders
    { userIdx: managerUser.id, status: 'delivered', items: [{ product_id: 1, quantity: 1, price_cents: 850 }], total: 850, ago: 300000 },
    { userIdx: managerUser.id, status: 'delivered', items: [{ product_id: 5, quantity: 2, price_cents: 1050 }], total: 2100, ago: 450000 },
    // Staff bot extra orders
    { userIdx: staffUser.id, status: 'delivered', items: [{ product_id: 2, quantity: 1, price_cents: 950 }], total: 950, ago: 380000 },
    { userIdx: staffUser.id, status: 'delivered', items: [{ product_id: 3, quantity: 2, price_cents: 750 }], total: 1500, ago: 530000 },
    // More Alice orders
    { userIdx: aliceUser.id, status: 'delivered', items: [{ product_id: 9, quantity: 1, price_cents: 800 }], total: 800, ago: 950000 },
    { userIdx: aliceUser.id, status: 'pending',   items: [{ product_id: 1, quantity: 1, price_cents: 850 }], total: 850, ago: 10000 },
    // More Bob orders
    { userIdx: bobUser.id, status: 'delivered', items: [{ product_id: 7, quantity: 1, price_cents: 1500 }], total: 1500, ago: 700000 },
    { userIdx: bobUser.id, status: 'delivered', items: [{ product_id: 8, quantity: 2, price_cents: 650 }], total: 1300, ago: 850000 },
    // Manager more
    { userIdx: managerUser.id, status: 'delivered', items: [{ product_id: 10, quantity: 1, price_cents: 1350 }], total: 1350, ago: 600000 },
    { userIdx: managerUser.id, status: 'delivered', items: [{ product_id: 4, quantity: 3, price_cents: 700 }], total: 2100, ago: 750000 },
  ];

  for (let i = 0; i < sampleOrderData.length; i++) {
    const od = sampleOrderData[i];
    const ts = now - od.ago - (i * 1000);  // stagger by 1s each to ensure unique UUIDs
    const orderId = mintUuidV1(ts);
    await Order.upsert({
      id: orderId,
      user_id: od.userIdx,
      status: od.status,
      items_json: od.items,
      total_price_cents: od.total,
      created_at: new Date(ts),
      updated_at: new Date(ts)
    });
  }

  // Seed secrets table with flag values
  const secretSeeds = [
    { key: 'inj01', value: getFlag('inj01') || 'JG{placeholder_inj01}' },
    { key: 'inj02', value: getFlag('inj02') || 'JG{placeholder_inj02}' },
    { key: 'ss01',  value: getFlag('ss01')  || 'JG{placeholder_ss01}' },
    { key: 'app_config', value: '{"version":"1.2.3","maintenance":false}' },
    { key: 'api_key', value: 'sk_live_garden_internal_key_abc123' },
  ];

  for (const s of secretSeeds) {
    await Secret.upsert(s);
  }

  // Seed a sample review (for CS-01 testing)
  await Review.upsert({
    id: 1,
    user_id: regularUsers[0].id,
    product_id: 1,
    content: 'Great juice! Really fresh.',
    rating: 5,
    approved: true,
    created_at: new Date(now - 5000)
  });

  // Advance the reviews sequence so Review.create() (without explicit id) gets
  // the next available id after seeded rows, avoiding a UNIQUE violation on id=1.
  await sequelize.query(
    "SELECT setval(pg_get_serial_sequence('reviews', 'id'), (SELECT MAX(id) FROM reviews))"
  );

  console.log('[db] Seed complete');
}

module.exports = { sequelize, initDb, User, Product, Order, Coupon, Review, Secret, Webhook, AuditLog, QueryTypes, restoreBotDefaults };
