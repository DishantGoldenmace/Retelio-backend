# StockMate Marketplace - Backend API

Robust Node.js backend server providing RESTful APIs, real-time functionality, and business logic for the StockMate marketplace platform.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env

# Start development server
npm run dev

# Build for production
npm run build && npm start
```

## 📋 Overview

The backend API serves as the central hub for all marketplace operations, providing:

- **RESTful APIs**: Comprehensive endpoints for all business operations
- **Authentication & Authorization**: JWT-based security with role-based access
- **Real-time Communication**: WebSocket support via Socket.io
- **Database Management**: MongoDB integration with Mongoose ODM
- **File Upload**: Image and document handling with AWS S3 integration
- **Payment Processing**: Stripe payment gateway integration
- **Email Services**: Automated email notifications
- **Logging & Monitoring**: Comprehensive logging and error tracking

## 🛠️ Tech Stack

- **Node.js 18+** - Runtime environment
- **Express.js** - Web framework and middleware
- **TypeScript** - Type-safe server development
- **MongoDB** - NoSQL database with AWS Atlas
- **Mongoose** - MongoDB ODM with schema validation
- **JWT** - JSON Web Tokens for authentication
- **bcrypt** - Password hashing and security
- **Socket.io** - Real-time bidirectional communication
- **Multer** - Multipart/form-data file upload handling
- **AWS SDK** - S3 integration for file storage
- **Joi** - Request data validation and sanitization
- **Nodemailer** - Email service integration
- **Winston** - Logging framework
- **Jest** - Testing framework
- **Swagger** - API documentation



## ⚙️ Configuration

### Environment Variables (.env)

```env
# Server Configuration
NODE_ENV=development
PORT=3001
HOST=localhost

# Database
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/stockmate
MONGODB_TEST_URI=mongodb+srv://username:password@cluster.mongodb.net/stockmate-test

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=7d
JWT_REFRESH_SECRET=your-refresh-token-secret
JWT_REFRESH_EXPIRES_IN=30d

# CORS Configuration
FRONTEND_URL=http://localhost:3000
ADMIN_URL=http://localhost:3002

# AWS Configuration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-s3-bucket-name

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Payment Configuration
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# External APIs
GOOGLE_ANALYTICS_API_KEY=your-analytics-key

# Logging
LOG_LEVEL=info
LOG_FILE=logs/app.log

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_MS=900000
```

## 🗄️ Database Models

### User Model

```typescript
// models/User.ts
import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: 'customer' | 'admin' | 'vendor';
  profile: {
    avatar?: string;
    phone?: string;
    address?: {
      street: string;
      city: string;
      state: string;
      zipCode: string;
      country: string;
    };
  };
  isEmailVerified: boolean;
  isActive: boolean;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
  },
  role: {
    type: String,
    enum: ['customer', 'admin', 'vendor'],
    default: 'customer',
  },
  // ... rest of schema
}, {
  timestamps: true,
});

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Instance method for password comparison
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export const User = model<IUser>('User', userSchema);
```

### Product Model

```typescript
// models/Product.ts
export interface IProduct extends Document {
  name: string;
  description: string;
  price: number;
  category: mongoose.Types.ObjectId;
  images: string[];
  inventory: {
    quantity: number;
    lowStockThreshold: number;
  };
  specifications: Record<string, any>;
  vendor: mongoose.Types.ObjectId;
  status: 'active' | 'inactive' | 'discontinued';
  ratings: {
    average: number;
    count: number;
  };
  seo: {
    title?: string;
    description?: string;
    keywords?: string[];
  };
}
```

## 🔐 Authentication & Authorization

### JWT Authentication Implementation

```typescript
// middleware/auth.middleware.ts
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { User } from '../models/User';

interface AuthRequest extends Request {
  user?: any;
}

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'Invalid token.' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token.' });
  }
};

export const authorize = (...roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Access denied.' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions.' });
    }

    next();
  };
};
```

## 📡 API Endpoints

### Authentication Endpoints

```typescript
// routes/auth.routes.ts
import { Router } from 'express';
import { 
  register, 
  login, 
  logout, 
  refreshToken, 
  forgotPassword, 
  resetPassword,
  verifyEmail
} from '../controllers/auth.controller';
import { validateRequest } from '../middleware/validation.middleware';
import { registerSchema, loginSchema } from '../utils/validators';

const router = Router();

router.post('/register', validateRequest(registerSchema), register);
router.post('/login', validateRequest(loginSchema), login);
router.post('/logout', logout);
router.post('/refresh-token', refreshToken);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.get('/verify-email/:token', verifyEmail);

export default router;
```

### Product Endpoints

```typescript
// controllers/product.controller.ts
export const getProducts = async (req: Request, res: Response) => {
  try {
    const {
      page = 1,
      limit = 10,
      category,
      minPrice,
      maxPrice,
      search,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const filter: any = { status: 'active' };
    
    if (category) filter.category = category;
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = Number(minPrice);
      if (maxPrice) filter.price.$lte = Number(maxPrice);
    }
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const products = await Product.find(filter)
      .populate('category', 'name')
      .populate('vendor', 'firstName lastName')
      .sort({ [sortBy as string]: sortOrder === 'desc' ? -1 : 1 })
      .limit(Number(limit) * 1)
      .skip((Number(page) - 1) * Number(limit))
      .exec();

    const total = await Product.countDocuments(filter);

    res.json({
      products,
      totalPages: Math.ceil(total / Number(limit)),
      currentPage: Number(page),
      totalProducts: total
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};
```

## 🔌 Socket.io Integration

### Real-time Order Updates

```typescript
// sockets/order.socket.ts
import { Server } from 'socket.io';
import { authenticate } from '../middleware/auth.middleware';

export const setupOrderSocket = (io: Server) => {
  const orderNamespace = io.of('/orders');
  
  orderNamespace.use(authenticate);
  
  orderNamespace.on('connection', (socket) => {
    console.log(`User ${socket.user.id} connected to orders`);
    
    // Join user-specific room for order updates
    socket.join(`user-${socket.user.id}`);
    
    socket.on('track-order', (orderId) => {
      socket.join(`order-${orderId}`);
    });

    socket.on('disconnect', () => {
      console.log(`User ${socket.user.id} disconnected from orders`);
    });
  });

  return {
    notifyOrderUpdate: (orderId: string, update: any) => {
      orderNamespace.to(`order-${orderId}`).emit('order-updated', update);
    },
    
    notifyUserOrder: (userId: string, order: any) => {
      orderNamespace.to(`user-${userId}`).emit('new-order', order);
    }
  };
};
```

## 💳 Payment Integration

### Stripe Payment Processing

```typescript
// services/payment.service.ts
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

export class PaymentService {
  static async createPaymentIntent(amount: number, currency = 'usd') {
    try {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency,
        automatic_payment_methods: {
          enabled: true,
        },
      });

      return {
        clientSecret: paymentIntent.client_secret,
        paymentIntentId: paymentIntent.id,
      };
    } catch (error) {
      throw new Error(`Payment intent creation failed: ${error.message}`);
    }
  }

  static async confirmPayment(paymentIntentId: string) {
    try {
      const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
      return paymentIntent.status === 'succeeded';
    } catch (error) {
      throw new Error(`Payment confirmation failed: ${error.message}`);
    }
  }

  static async handleWebhook(payload: any, signature: string) {
    try {
      const event = stripe.webhooks.constructEvent(
        payload,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET!
      );

      switch (event.type) {
        case 'payment_intent.succeeded':
          // Handle successful payment
          break;
        case 'payment_intent.payment_failed':
          // Handle failed payment
          break;
        default:
          console.log(`Unhandled event type ${event.type}`);
      }

      return { received: true };
    } catch (error) {
      throw new Error(`Webhook handling failed: ${error.message}`);
    }
  }
}
```

## 📧 Email Services

### Email Service Implementation

```typescript
// services/email.service.ts
import nodemailer from 'nodemailer';
import { IUser } from '../models/User';

const transporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export class EmailService {
  static async sendWelcomeEmail(user: IUser) {
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: user.email,
      subject: 'Welcome to StockMate Marketplace',
      html: `
        <h1>Welcome ${user.firstName}!</h1>
        <p>Thank you for joining StockMate Marketplace.</p>
        <p>Start exploring our amazing products today!</p>
      `,
    };

    await transporter.sendMail(mailOptions);
  }

  static async sendOrderConfirmation(user: IUser, order: any) {
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: user.email,
      subject: `Order Confirmation - #${order.orderNumber}`,
      html: `
        <h1>Order Confirmed!</h1>
        <p>Hi ${user.firstName},</p>
        <p>Your order #${order.orderNumber} has been confirmed.</p>
        <p>Total: $${order.totalAmount}</p>
      `,
    };

    await transporter.sendMail(mailOptions);
  }
}
```

## 🧪 Testing

### Testing Configuration

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**/*',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};
```

### Example Tests

```typescript
// tests/integration/auth.test.ts
import request from 'supertest';
import { app } from '../../src/app';
import { User } from '../../src/models/User';

describe('Authentication Endpoints', () => {
  beforeEach(async () => {
    await User.deleteMany({});
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body.user.email).toBe(userData.email);
    });

    it('should not register user with existing email', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      };

      await User.create(userData);

      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);
    });
  });
});
```

## 🚀 Development Scripts

```bash
# Development
npm run dev            # Start development server with nodemon
npm run dev:debug      # Start with debugging enabled

# Building
npm run build          # Compile TypeScript to JavaScript
npm run build:watch    # Build in watch mode

# Testing
npm test               # Run all tests
npm run test:watch     # Run tests in watch mode
npm run test:coverage  # Run tests with coverage report
npm run test:unit      # Run unit tests only
npm run test:integration # Run integration tests only

# Database
npm run seed           # Seed database with sample data
npm run migrate        # Run database migrations

# Code Quality
npm run lint           # Run ESLint
npm run lint:fix       # Fix ESLint issues
npm run format         # Format code with Prettier
npm run type-check     # TypeScript type checking

# Production
npm start              # Start production server
npm run pm2:start      # Start with PM2 process manager
```

## 📊 Logging and Monitoring

### Winston Logger Configuration

```typescript
// utils/logger.ts
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'stockmate-backend' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

export default logger;
```

## 🐛 Error Handling

### Global Error Middleware

```typescript
// middleware/error.middleware.ts
import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

export const errorHandler = (
  error: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  logger.error('Error occurred:', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
  });

  if (error.name === 'ValidationError') {
    return res.status(400).json({
      message: 'Validation Error',
      errors: Object.values(error.errors).map((err: any) => err.message),
    });
  }

  if (error.name === 'CastError') {
    return res.status(400).json({
      message: 'Invalid ID format',
    });
  }

  if (error.code === 11000) {
    return res.status(400).json({
      message: 'Duplicate field value',
    });
  }

  res.status(error.statusCode || 500).json({
    message: error.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack }),
  });
};
```

## 🚀 Deployment

### Docker Configuration

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3001

USER node

CMD ["npm", "start"]
```

### Production Considerations

- Use PM2 for process management
- Implement proper logging and monitoring
- Set up database backups
- Configure load balancing
- Enable HTTPS with SSL certificates
- Set up environment-specific configurations

---

## 🤝 Contributing

Follow the project's contributing guidelines and maintain code quality standards.

### API Documentation

API documentation is automatically generated using Swagger and available at `/api-docs` when the server is running.

---

**For questions and support, refer to the main project documentation.**