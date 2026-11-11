// ============================================================================
// BackendCore.cpp - Kimi K2.6 300-Agent Swarm
// Backend Core - 100 parallel backend agents
// ============================================================================

#include "BackendCore.hpp"
#include <sstream>
#include <algorithm>

namespace rawrxd {
namespace swarm {

// Main generation function
BackendCore::GeneratedBackend BackendCore::generateBackend(const BackendRequest& request) {
    GeneratedBackend backend;
    
    // Generate service files
    for (const auto& service : request.services) {
        backend.serviceFiles[service.name + ".ts"] = generateService(service, request.stack);
        backend.routeFiles[service.name + ".routes.ts"] = generateRoutes(service, request.stack);
    }
    
    // Generate model files
    backend.modelFiles["index.ts"] = generateModels(request.database, request.stack);
    
    // Generate middleware
    backend.middlewareFiles["auth.ts"] = generateAuthMiddleware(request.authStrategy);
    backend.middlewareFiles["error.ts"] = generateErrorHandling();
    
    // Generate config files
    backend.configFiles["database.ts"] = generateORMConfig(request.stack);
    
    // Generate main entry
    backend.mainEntry = generateMainEntry(request);
    
    // Generate Dockerfile
    backend.dockerfile = generateDockerfile(request.stack);
    
    // Generate test files
    for (const auto& service : request.services) {
        backend.testFiles[service.name + ".test.ts"] = generateIntegrationTests(service);
    }
    
    return backend;
}

// Service generator
std::string BackendCore::generateService(const ServiceSpec& spec, const TechStack& stack) {
    std::stringstream ss;
    
    ss << "import { PrismaClient } from '@prisma/client';\n";
    ss << "const prisma = new PrismaClient();\n\n";
    
    ss << "export class " << spec.name << "Service {\n";
    
    for (const auto& endpoint : spec.endpoints) {
        ss << "  async " << endpoint.name << "(";
        for (size_t i = 0; i < endpoint.parameters.size(); ++i) {
            ss << endpoint.parameters[i].first << ": " << endpoint.parameters[i].second;
            if (i < endpoint.parameters.size() - 1) ss << ", ";
        }
        ss << ") {\n";
        ss << "    // Implementation\n";
        ss << "    return {};\n";
        ss << "  }\n\n";
    }
    
    ss << "}\n";
    
    return ss.str();
}

// Controller generator
std::string BackendCore::generateController(const ServiceSpec& spec, const TechStack& stack) {
    std::stringstream ss;
    
    ss << "import { Request, Response } from 'express';\n";
    ss << "import { " << spec.name << "Service } from './" << spec.name << "';\n\n";
    
    ss << "export class " << spec.name << "Controller {\n";
    ss << "  private service = new " << spec.name << "Service();\n\n";
    
    for (const auto& endpoint : spec.endpoints) {
        ss << "  async " << endpoint.name << "(req: Request, res: Response) {\n";
        ss << "    try {\n";
        ss << "      const result = await this.service." << endpoint.name << "();\n";
        ss << "      res.json(result);\n";
        ss << "    } catch (error) {\n";
        ss << "      res.status(500).json({ error: error.message });\n";
        ss << "    }\n";
        ss << "  }\n\n";
    }
    
    ss << "}\n";
    
    return ss.str();
}

// Routes generator
std::string BackendCore::generateRoutes(const ServiceSpec& spec, const TechStack& stack) {
    std::stringstream ss;
    
    ss << "import { Router } from 'express';\n";
    ss << "import { " << spec.name << "Controller } from './" << spec.name << ".controller';\n";
    ss << "import { authMiddleware } from '../middleware/auth';\n\n";
    
    ss << "const router = Router();\n";
    ss << "const controller = new " << spec.name << "Controller();\n\n";
    
    for (const auto& endpoint : spec.endpoints) {
        ss << "router." << endpoint.method << "('" << endpoint.path << "', ";
        if (endpoint.requiresAuth) {
            ss << "authMiddleware, ";
        }
        ss << "controller." << endpoint.name << ".bind(controller));\n";
    }
    
    ss << "\nexport default router;\n";
    
    return ss.str();
}

// Models generator
std::string BackendCore::generateModels(const DatabaseSchema& schema, const TechStack& stack) {
    std::stringstream ss;
    
    ss << "// Prisma schema models\n\n";
    
    for (const auto& table : schema.tables) {
        ss << "model " << table.name << " {\n";
        for (const auto& col : table.columns) {
            ss << "  " << col.first << " " << col.second;
            if (std::find(table.primaryKeys.begin(), table.primaryKeys.end(), col.first) != table.primaryKeys.end()) {
                ss << " @id";
            }
            ss << "\n";
        }
        ss << "}\n\n";
    }
    
    return ss.str();
}

// Migration generator
std::string BackendCore::generateMigrations(const DatabaseSchema& schema) {
    std::stringstream ss;
    ss << "-- Migration for " << schema.databaseType << "\n\n";
    
    for (const auto& table : schema.tables) {
        ss << "CREATE TABLE " << table.name << " (\n";
        for (size_t i = 0; i < table.columns.size(); ++i) {
            ss << "  " << table.columns[i].first << " " << table.columns[i].second;
            if (i < table.columns.size() - 1) ss << ",";
            ss << "\n";
        }
        ss << ");\n\n";
    }
    
    return ss.str();
}

// Seed generator
std::string BackendCore::generateSeeds(const DatabaseSchema& schema) {
    std::stringstream ss;
    ss << "// Database seeds\n\n";
    ss << "export async function seed() {\n";
    ss << "  // Add seed data\n";
    ss << "}\n";
    return ss.str();
}

// ORM config generator
std::string BackendCore::generateORMConfig(const TechStack& stack) {
    return R"(import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient({
  log: ['query', 'info', 'warn', 'error'],
});

export default prisma;
)";
}

// Auth middleware generator
std::string BackendCore::generateAuthMiddleware(const std::string& strategy) {
    if (strategy == "jwt") {
        return R"(import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    (req as any).user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
})";
    }
    return "// Auth middleware placeholder\n";
}

// JWT config generator
std::string BackendCore::generateJWTConfig() {
    return R"({
  "secret": process.env.JWT_SECRET,
  "expiresIn": "7d",
  "algorithm": "HS256"
})";
}

// Password hashing generator
std::string BackendCore::generatePasswordHashing() {
    return R"(import bcrypt from 'bcrypt';

export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
})";
}

// CSRF protection generator
std::string BackendCore::generateCSRFProtection() {
    return R"(import csrf from 'csurf';

export const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});)";
}

// Rate limiter generator
std::string BackendCore::generateRateLimiter(const std::string& config) {
    return R"(import rateLimit from 'express-rate-limit';

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});)";
}

// Error handling generator
std::string BackendCore::generateErrorHandling() {
    return R"(import { Request, Response, NextFunction } from 'express';

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) {
  console.error(err.stack);
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
})";
}

// API documentation generator
std::string BackendCore::generateAPIDocumentation(const std::vector<ServiceSpec>& services) {
    std::stringstream ss;
    ss << "# API Documentation\n\n";
    
    for (const auto& service : services) {
        ss << "## " << service.name << "\n\n";
        for (const auto& endpoint : service.endpoints) {
            ss << "### " << endpoint.method << " " << endpoint.path << "\n";
            ss << endpoint.description << "\n\n";
        }
    }
    
    return ss.str();
}

// OpenAPI spec generator
std::string BackendCore::generateOpenAPISpec(const std::vector<ServiceSpec>& services) {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"openapi\": \"3.0.0\",\n";
    ss << "  \"info\": {\n";
    ss << "    \"title\": \"API\",\n";
    ss << "    \"version\": \"1.0.0\"\n";
    ss << "  },\n";
    ss << "  \"paths\": {\n";
    ss << "    // Add paths here\n";
    ss << "  }\n";
    ss << "}\n";
    return ss.str();
}

// Integration generators
std::string BackendCore::generateStripeIntegration(const std::vector<std::string>& features) {
    return R"(import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16'
});

export async function createPaymentIntent(amount: number) {
  return stripe.paymentIntents.create({
    amount: amount * 100, // Convert to cents
    currency: 'usd'
  });
})";
}

std::string BackendCore::generateAuth0Integration() {
    return R"(import { auth } from 'express-oauth2-jwt-bearer';

export const checkJwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER
});)";
}

std::string BackendCore::generateSendGridIntegration() {
    return R"(import sgMail from '@sendgrid/mail';

sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

export async function sendEmail(to: string, subject: string, html: string) {
  return sgMail.send({ to, from: process.env.FROM_EMAIL!, subject, html });
})";
}

std::string BackendCore::generateS3Integration() {
    return R"(import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

const s3 = new S3Client({ region: process.env.AWS_REGION });

export async function uploadFile(key: string, body: Buffer) {
  return s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET!,
    Key: key,
    Body: body
  }));
})";
}

std::string BackendCore::generateRedisIntegration() {
    return R"(import { createClient } from 'redis';

const client = createClient({ url: process.env.REDIS_URL });

export async function getCache(key: string) {
  return client.get(key);
}

export async function setCache(key: string, value: string, ttl: number) {
  return client.setEx(key, ttl, value);
})";
}

std::string BackendCore::generateElasticsearchIntegration() {
    return R"(import { Client } from '@elastic/elasticsearch';

const client = new Client({ node: process.env.ELASTICSEARCH_URL });

export async function search(index: string, query: any) {
  return client.search({ index, body: { query } });
})";
}

// Real-time features
std::string BackendCore::generateWebSocketHandler(const std::string& feature) {
    return R"(import { WebSocket } from 'ws';

export function handleWebSocket(ws: WebSocket) {
  ws.on('message', (data) => {
    // Handle message
  });
  
  ws.on('close', () => {
    // Handle disconnect
  });
})";
}

std::string BackendCore::generateSSEEndpoint(const std::string& feature) {
    return R"(import { Request, Response } from 'express';

export function sseHandler(req: Request, res: Response) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  // Send events
  const interval = setInterval(() => {
    res.write(`data: ${JSON.stringify({ time: Date.now() })}

`);
  }, 1000);
  
  req.on('close', () => {
    clearInterval(interval);
  });
})";
}

std::string BackendCore::generateGraphQLSchema(const std::vector<ServiceSpec>& services) {
    std::stringstream ss;
    ss << "type Query {\n";
    for (const auto& service : services) {
        for (const auto& endpoint : service.endpoints) {
            if (endpoint.method == "GET") {
                ss << "  " << endpoint.name << ": String\n";
            }
        }
    }
    ss << "}\n\n";
    ss << "type Mutation {\n";
    ss << "  // Add mutations\n";
    ss << "}\n";
    return ss.str();
}

std::string BackendCore::generateGraphQLResolvers(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "export const resolvers = {\n";
    ss << "  Query: {\n";
    for (const auto& endpoint : spec.endpoints) {
        if (endpoint.method == "GET") {
            ss << "    " << endpoint.name << ": () => {\n";
            ss << "      // Implementation\n";
            ss << "    },\n";
        }
    }
    ss << "  }\n";
    ss << "};\n";
    return ss.str();
}

// Testing generators
std::string BackendCore::generateIntegrationTests(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "import request from 'supertest';\n";
    ss << "import { app } from '../app';\n\n";
    ss << "describe('" << spec.name << "', () => {\n";
    for (const auto& endpoint : spec.endpoints) {
        ss << "  describe('" << endpoint.method << " " << endpoint.path << "', () => {\n";
        ss << "    it('should return 200', async () => {\n";
        ss << "      const res = await request(app)." << endpoint.method << "('" << endpoint.path << "');\n";
        ss << "      expect(res.status).toBe(200);\n";
        ss << "    });\n";
        ss << "  });\n";
    }
    ss << "});\n";
    return ss.str();
}

std::string BackendCore::generateLoadTest(const APIEndpoint& endpoint) {
    std::stringstream ss;
    ss << "import http from 'k6/http';\n";
    ss << "import { check } from 'k6';\n\n";
    ss << "export const options = {\n";
    ss << "  stages: [\n";
    ss << "    { duration: '1m', target: 100 },\n";
    ss << "    { duration: '3m', target: 100 },\n";
    ss << "    { duration: '1m', target: 0 }\n";
    ss << "  ]\n";
    ss << "};\n\n";
    ss << "export default function() {\n";
    ss << "  const res = http." << endpoint.method << "('http://localhost:3001" << endpoint.path << "');\n";
    ss << "  check(res, {\n";
    ss << "    'status is 200': (r) => r.status === 200\n";
    ss << "  });\n";
    ss << "}\n";
    return ss.str();
}

std::string BackendCore::generateContractTests(const std::vector<ServiceSpec>& services) {
    return R"(import { Pact } from '@pact-foundation/pact';

describe('API Contracts', () => {
  const provider = new Pact({
    consumer: 'frontend',
    provider: 'backend'
  });

  // Add contract tests here
});)";
}

// Framework-specific generators
std::string BackendCore::generateExpressService(const ServiceSpec& spec) {
    return generateService(spec, TechStack{});
}

std::string BackendCore::generateFastAPIService(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "from fastapi import FastAPI, HTTPException\n";
    ss << "from pydantic import BaseModel\n\n";
    ss << "app = FastAPI()\n\n";
    
    for (const auto& endpoint : spec.endpoints) {
        ss << "@app." << endpoint.method << "('" << endpoint.path << "')\n";
        ss << "async def " << endpoint.name << "():\n";
        ss << "    return {}\n\n";
    }
    
    return ss.str();
}

std::string BackendCore::generateSpringService(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "package com.example." << spec.name << ";\n\n";
    ss << "import org.springframework.web.bind.annotation.*;\n\n";
    ss << "@RestController\n";
    ss << "@RequestMapping(\"/api/v1\")\n";
    ss << "public class " << spec.name << "Controller {\n\n";
    
    for (const auto& endpoint : spec.endpoints) {
        ss << "    @" << endpoint.method << "Mapping(\"" << endpoint.path << "\")\n";
        ss << "    public ResponseEntity<?> " << endpoint.name << "() {\n";
        ss << "        return ResponseEntity.ok().build();\n";
        ss << "    }\n\n";
    }
    
    ss << "}\n";
    return ss.str();
}

std::string BackendCore::generateDotNetService(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "using Microsoft.AspNetCore.Mvc;\n\n";
    ss << "namespace " << spec.name << "Controller {\n\n";
    ss << "[ApiController]\n";
    ss << "[Route(\"api/v1\")]\n";
    ss << "public class " << spec.name << "Controller : ControllerBase {\n\n";
    
    for (const auto& endpoint : spec.endpoints) {
        ss << "        [Http" << endpoint.method << "(\"" << endpoint.path << "\")]\n";
        ss << "        public IActionResult " << endpoint.name << "() {\n";
        ss << "            return Ok();\n";
        ss << "        }\n\n";
    }
    
    ss << "    }\n";
    ss << "}\n";
    return ss.str();
}

// Deployment generators
std::string BackendCore::generatePM2Config() {
    return R"(module.exports = {
  apps: [{
    name: 'api',
    script: './dist/index.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    }
  }]
};)";
}

std::string BackendCore::generateNginxConfig(const std::vector<ServiceSpec>& services) {
    return R"(server {
  listen 80;
  server_name api.example.com;

  location / {
    proxy_pass http://localhost:3001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
  }
})";
}

std::string BackendCore::generateK8sDeployment(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "apiVersion: apps/v1\n";
    ss << "kind: Deployment\n";
    ss << "metadata:\n";
    ss << "  name: " << spec.name << "\n";
    ss << "spec:\n";
    ss << "  replicas: 3\n";
    ss << "  selector:\n";
    ss << "    matchLabels:\n";
    ss << "      app: " << spec.name << "\n";
    ss << "  template:\n";
    ss << "    metadata:\n";
    ss << "      labels:\n";
    ss << "        app: " << spec.name << "\n";
    ss << "    spec:\n";
    ss << "      containers:\n";
    ss << "      - name: " << spec.name << "\n";
    ss << "        image: " << spec.name << ":latest\n";
    ss << "        ports:\n";
    ss << "        - containerPort: 3001\n";
    return ss.str();
}

std::string BackendCore::generateK8sService(const ServiceSpec& spec) {
    std::stringstream ss;
    ss << "apiVersion: v1\n";
    ss << "kind: Service\n";
    ss << "metadata:\n";
    ss << "  name: " << spec.name << "\n";
    ss << "spec:\n";
    ss << "  selector:\n";
    ss << "    app: " << spec.name << "\n";
    ss << "  ports:\n";
    ss << "  - port: 80\n";
    ss << "    targetPort: 3001\n";
    return ss.str();
}

std::string BackendCore::generateHealthCheck() {
    return R"(import { Request, Response } from 'express';

export function healthCheck(req: Request, res: Response) {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
})";
}

std::string BackendCore::generateMetricsEndpoint() {
    return R"(import { Request, Response } from 'express';
import { register } from 'prom-client';

export async function metricsEndpoint(req: Request, res: Response) {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
})";
}

// Main entry generator
std::string BackendCore::generateMainEntry(const BackendRequest& request) {
    std::stringstream ss;
    ss << "import express from 'express';\n";
    ss << "import cors from 'cors';\n";
    ss << "import helmet from 'helmet';\n\n";
    
    for (const auto& service : request.services) {
        ss << "import " << service.name << "Routes from './routes/" << service.name << "';\n";
    }
    
    ss << "\nconst app = express();\n\n";
    ss << "// Middleware\n";
    ss << "app.use(helmet());\n";
    ss << "app.use(cors());\n";
    ss << "app.use(express.json());\n\n";
    
    ss << "// Routes\n";
    for (const auto& service : request.services) {
        ss << "app.use('/api/v1', " << service.name << "Routes);\n";
    }
    
    ss << "\n// Health check\n";
    ss << "app.get('/health', (req, res) => {\n";
    ss << "  res.json({ status: 'ok' });\n";
    ss << "});\n\n";
    
    ss << "const PORT = process.env.PORT || 3001;\n";
    ss << "app.listen(PORT, () => {\n";
    ss << "  console.log(`Server running on port ${PORT}`);\n";
    ss << "});\n";
    
    return ss.str();
}

// Dockerfile generator
std::string BackendCore::generateDockerfile(const TechStack& stack) {
    return R"(FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./
EXPOSE 3001
CMD ["node", "dist/index.js"])";
}

} // namespace swarm
} // namespace rawrxd
