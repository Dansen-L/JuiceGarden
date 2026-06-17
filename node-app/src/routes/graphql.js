/**
 * GraphQL endpoint
 * BAC-03: BOLA — resolver doesn't check ownership
 * Introspection enabled and unfiltered (reveals adminNotes field)
 */
'use strict';

const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const { Order, User } = require('../models');
const { getFlag } = require('../utils/flags');

const router = express.Router();

// GraphQL schema — includes hidden adminNotes field discoverable via introspection
const schema = buildSchema(`
  type Product {
    id: Int
    name: String
    price_cents: Int
    category: String
  }

  type OrderItem {
    product_id: Int
    quantity: Int
    price_cents: Int
  }

  type Order {
    id: String
    status: String
    total_price_cents: Int
    created_at: String
    items: [OrderItem]
    adminNotes: String
  }

  type Query {
    order(id: String!): Order
    myOrders: [Order]
    products: [Product]
  }
`);

const root = {
  // BAC-03 VULNERABILITY: no ownership check on order resolver
  order: async ({ id }, context) => {
    const order = await Order.findByPk(id);
    if (!order) return null;

    const bac03Flag = getFlag('bac03');

    // Check if this is an admin-owned order
    const owner = await User.findByPk(order.user_id);
    const isAdminOrder = owner && owner.role === 'admin';

    return {
      id: order.id,
      status: order.status,
      total_price_cents: order.total_price_cents,
      created_at: order.created_at ? order.created_at.toISOString() : null,
      items: order.items_json || [],
      // BAC-03: adminNotes revealed without ownership check
      // Contains flag for admin-owned orders
      adminNotes: isAdminOrder ? `ADMIN_CONFIDENTIAL: ${bac03Flag}` : null
    };
  },

  myOrders: async (args, context) => {
    if (!context.user) return [];
    const orders = await Order.findAll({ where: { user_id: context.user.id } });
    return orders.map(o => ({
      id: o.id,
      status: o.status,
      total_price_cents: o.total_price_cents,
      created_at: o.created_at ? o.created_at.toISOString() : null,
      items: o.items_json || [],
      adminNotes: null
    }));
  },

  products: async () => {
    const { Product } = require('../models');
    const products = await Product.findAll({ where: { is_active: true } });
    return products.map(p => ({
      id: p.id,
      name: p.name,
      price_cents: p.price_cents,
      category: p.category
    }));
  }
};

// Mount GraphQL with introspection enabled (unfiltered — BAC-03 discovery path)
router.use('/', (req, res, next) => {
  const user = req.session && req.session.userId
    ? { id: req.session.userId, role: req.session.role }
    : null;

  graphqlHTTP({
    schema,
    rootValue: root,
    graphiql: true,  // BAC-03: GraphiQL explorer enables introspection discovery
    context: { user }
  })(req, res, next);
});

module.exports = router;
