
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import stripe from './stripe.js';
import { products as initialProducts } from './products.js';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

const app = express();
app.use(cors());
app.use(express.json());

// Log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Simple in-memory user store (temporary - MongoDB disabled)
let users = [];
let nextUserId = 1;

// In-memory appointments store
let appointments = [];
let nextAppointmentId = 1;

// JWT auth middleware
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
// NOTE: MongoDB / Mongoose disabled for now. Using in-memory users for auth.
// Signup endpoint (in-memory)
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: nextUserId++, email, password: hashed };
  users.push(user);

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

// Login endpoint (in-memory)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});


// ...existing code...

app.get('/', (req, res) => {
  res.send('Chi\'s Luxe Beauties backend API running');
});

// In-memory data (replace with DB in production)
let products = [...initialProducts];
let orders = [];
let nextProductId = products.length ? Math.max(...products.map(p => p.id)) + 1 : 1;
let nextOrderId = 1;

// Products API
app.get('/api/products', (req, res) => {
  res.json(products);
});

// Get single product by ID
app.get('/api/products/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const product = products.find(p => p.id === id);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  res.json(product);
});

// Get all orders (for admin or user order history)
app.get('/api/orders', (req, res) => {
  res.json(orders);
});

app.post('/api/products', (req, res) => {
  const { name, price, image, description } = req.body;
  if (!name || typeof name !== 'string' || !price || typeof price !== 'number' || !image || typeof image !== 'string' || !description || typeof description !== 'string') {
    return res.status(400).json({ error: 'All fields (name, price, image, description) are required and must be valid.' });
  }
  const product = { id: nextProductId++, name, price, image, description };
  products.push(product);
  res.status(201).json(product);
});

app.put('/api/products/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const idx = products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });
  const { name, price, image, description } = req.body;
  if (!name || typeof name !== 'string' || !price || typeof price !== 'number' || !image || typeof image !== 'string' || !description || typeof description !== 'string') {
    return res.status(400).json({ error: 'All fields (name, price, image, description) are required and must be valid.' });
  }
  products[idx] = { ...products[idx], name, price, image, description };
  res.json(products[idx]);
});

app.delete('/api/products/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const idx = products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });
  products.splice(idx, 1);
  res.json({ success: true });
});

// Orders API (protected)
app.post('/api/orders', auth, (req, res) => {
  const { items, total, customer, paymentIntentId } = req.body;
  if (!items || !Array.isArray(items) || typeof total !== 'number' || !customer || typeof customer !== 'object' || !paymentIntentId) {
    return res.status(400).json({ error: 'Invalid order data' });
  }
  // Optionally verify paymentIntent status with Stripe
  orders.push({ id: nextOrderId++, items, total, customer, paymentIntentId, userId: req.user.userId, date: new Date().toISOString() });
  res.status(201).json({ success: true });
});

// Stripe payment intent endpoint (protected)
app.post('/api/create-payment-intent', auth, async (req, res) => {
  const { amount, currency = 'usd' } = req.body;
  if (!amount || typeof amount !== 'number') return res.status(400).json({ error: 'Amount required' });
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // dollars to cents
      currency,
      metadata: { userId: req.user.userId },
      automatic_payment_methods: { enabled: true },
    });
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    res.status(500).json({ error: 'Payment error', details: err.message });
  }
});

// Stripe webhook for payment status (optional, for production)
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  // Handle event types (e.g., payment_intent.succeeded)
  if (event.type === 'payment_intent.succeeded') {
    // Optionally update order status in DB
  }
  res.json({ received: true });
});

// Appointments API
// Get all appointments
app.get('/api/appointments', (req, res) => {
  res.json(appointments);
});

// Get appointments for logged-in user
app.get('/api/appointments/my', auth, (req, res) => {
  const userAppointments = appointments.filter(a => a.userId === req.user.userId);
  res.json(userAppointments);
});

// Create new appointment (protected)
app.post('/api/appointments', auth, (req, res) => {
  const { service, date, time, notes, customerName, customerPhone, customerEmail, stylistId } = req.body;
  if (!service || !date || !time) {
    return res.status(400).json({ error: 'Service, date, and time are required' });
  }
  
  const appointment = {
    id: nextAppointmentId++,
    userId: req.user.userId,
    service,
    date,
    time,
    notes: notes || '',
    customerName: customerName || '',
    customerPhone: customerPhone || '',
    customerEmail: customerEmail || '',
    stylistId: stylistId || null,
    status: 'pending_payment', // Changed from 'pending' to 'pending_payment'
    paymentStatus: 'unpaid',
    depositPaid: false,
    createdAt: new Date().toISOString(),
  };
  
  appointments.push(appointment);
  res.status(201).json(appointment);
});

// Update appointment status (admin/protected)
app.put('/api/appointments/:id', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = appointments.findIndex(a => a.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Appointment not found' });
  
  const { status, notes } = req.body;
  if (status) appointments[idx].status = status;
  if (notes !== undefined) appointments[idx].notes = notes;
  
  res.json(appointments[idx]);
});

// Delete appointment
app.delete('/api/appointments/:id', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = appointments.findIndex(a => a.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Appointment not found' });
  
  appointments.splice(idx, 1);
  res.json({ success: true });
});

// Confirm appointment payment (mark deposit as paid)
app.post('/api/appointments/:id/confirm-payment', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const { paymentIntentId, depositAmount } = req.body;
  const idx = appointments.findIndex(a => a.id === id);
  
  if (idx === -1) return res.status(404).json({ error: 'Appointment not found' });
  
  // Update appointment with payment info
  appointments[idx].depositPaid = true;
  appointments[idx].paymentStatus = 'deposit_paid';
  appointments[idx].paymentIntentId = paymentIntentId;
  appointments[idx].depositAmount = depositAmount;
  appointments[idx].status = 'pending'; // Change from pending_payment to pending (awaiting admin confirmation)
  appointments[idx].paidAt = new Date().toISOString();
  
  res.json(appointments[idx]);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 Chi's Luxe Beauties Backend Server Running!`);
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`\n✅ Available Endpoints:`);
  console.log(`   - POST   /api/signup`);
  console.log(`   - POST   /api/login`);
  console.log(`   - GET    /api/products`);
  console.log(`   - POST   /api/products (auth)`);
  console.log(`   - PUT    /api/products/:id (auth)`);
  console.log(`   - DELETE /api/products/:id (auth)`);
  console.log(`   - GET    /api/appointments`);
  console.log(`   - GET    /api/appointments/my (auth)`);
  console.log(`   - POST   /api/appointments (auth)`);
  console.log(`   - PUT    /api/appointments/:id (auth)`);
  console.log(`   - DELETE /api/appointments/:id (auth)`);
  console.log(`   - POST   /api/appointments/:id/confirm-payment (auth)`);
  console.log(`   - POST   /api/create-payment-intent (auth)`);
  console.log(`   - POST   /api/orders (auth)`);
  console.log(`\n👥 In-memory storage active (MongoDB disabled)`);
  console.log(`📊 Current Data: ${users.length} users, ${products.length} products, ${appointments.length} appointments\n`);
});
