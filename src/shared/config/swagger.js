/**
 * swagger.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OpenAPI 3.0 spec setup using swagger-jsdoc + swagger-ui-express.
 * Exposes /docs (interactive UI) and /docs.json (raw spec).
 * ─────────────────────────────────────────────────────────────────────────────
 */

import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const definition = {
  openapi: '3.0.0',
  info: {
    title:       'Secure Financial Backend API',
    version:     '1.0.0',
    description: 'FAANG-level financial data processing & access control backend',
    contact: { name: 'Engineering Team', email: 'engineering@example.com' },
  },
  servers: [
    { url: '/api/v1', description: 'Current version' },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type:         'http',
        scheme:       'bearer',
        bearerFormat: 'JWT',
        description:  'Access token obtained from POST /auth/login',
      },
    },
    schemas: {
      // ── Finance ──────────────────────────────────────
      CreateTransactionInput: {
        type:     'object',
        required: ['type', 'amount', 'description', 'date'],
        properties: {
          type:        { type: 'string', enum: ['INCOME', 'EXPENSE'] },
          amount:      { type: 'string', example: '1500.00', description: 'Decimal string, max 2dp' },
          currency:    { type: 'string', example: 'USD', default: 'USD' },
          description: { type: 'string', maxLength: 255 },
          notes:       { type: 'string', maxLength: 1000 },
          date:        { type: 'string', format: 'date-time' },
          categoryId:  { type: 'string', format: 'uuid', nullable: true },
          accountId:   { type: 'string', format: 'uuid', nullable: true },
        },
      },
      UpdateTransactionInput: {
        type: 'object',
        properties: {
          type:        { type: 'string', enum: ['INCOME', 'EXPENSE'] },
          amount:      { type: 'string', example: '1500.00' },
          currency:    { type: 'string', example: 'USD' },
          description: { type: 'string', maxLength: 255 },
          notes:       { type: 'string', maxLength: 1000, nullable: true },
          date:        { type: 'string', format: 'date-time' },
          categoryId:  { type: 'string', format: 'uuid', nullable: true },
          accountId:   { type: 'string', format: 'uuid', nullable: true },
        },
      },
      TransactionResponse: {
        type: 'object',
        properties: {
          success:   { type: 'boolean' },
          message:   { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
          data: {
            type: 'object',
            properties: {
              transaction: { $ref: '#/components/schemas/Transaction' },
            },
          },
        },
      },
      Transaction: {
        type: 'object',
        properties: {
          id:          { type: 'string', format: 'uuid' },
          userId:      { type: 'string', format: 'uuid' },
          type:        { type: 'string', enum: ['INCOME', 'EXPENSE'] },
          amount:      { type: 'string', description: 'Decimal string' },
          currency:    { type: 'string' },
          description: { type: 'string' },
          notes:       { type: 'string', nullable: true },
          date:        { type: 'string', format: 'date-time' },
          deletedAt:   { type: 'string', format: 'date-time', nullable: true },
          createdAt:   { type: 'string', format: 'date-time' },
          updatedAt:   { type: 'string', format: 'date-time' },
          category: {
            type: 'object', nullable: true,
            properties: {
              id: { type: 'string' }, name: { type: 'string' },
              color: { type: 'string' }, icon: { type: 'string' },
            },
          },
          account: {
            type: 'object', nullable: true,
            properties: {
              id: { type: 'string' }, name: { type: 'string' }, type: { type: 'string' },
            },
          },
        },
      },
      PaginatedTransactions: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          data: {
            type: 'object',
            properties: {
              transactions: { type: 'array', items: { $ref: '#/components/schemas/Transaction' } },
              pagination: {
                type: 'object',
                properties: {
                  total:   { type: 'integer' },
                  page:    { type: 'integer' },
                  limit:   { type: 'integer' },
                  pages:   { type: 'integer' },
                  hasNext: { type: 'boolean' },
                  hasPrev: { type: 'boolean' },
                },
              },
            },
          },
        },
      },
      CreateCategoryInput: {
        type:     'object',
        required: ['name', 'type'],
        properties: {
          name:  { type: 'string', maxLength: 50 },
          type:  { type: 'string', enum: ['INCOME', 'EXPENSE'] },
          color: { type: 'string', example: '#4CAF50' },
          icon:  { type: 'string', example: '💼' },
        },
      },
    },
    responses: {
      ValidationError: {
        description: 'Request validation failed',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                code:    { type: 'string',  example: 'VALIDATION_ERROR' },
                message: { type: 'string',  example: 'Validation failed' },
                errors:  {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      field:   { type: 'string' },
                      message: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      Unauthorized: {
        description: 'Missing or invalid authentication',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                code:    { type: 'string',  example: 'AUTH_REQUIRED' },
                message: { type: 'string' },
              },
            },
          },
        },
      },
      Forbidden: {
        description: 'Insufficient permissions',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                code:    { type: 'string',  example: 'FORBIDDEN' },
                message: { type: 'string' },
              },
            },
          },
        },
      },
      NotFound: {
        description: 'Resource not found',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean', example: false },
                code:    { type: 'string',  example: 'NOT_FOUND' },
                message: { type: 'string' },
              },
            },
          },
        },
      },
    },
  },
  security: [{ bearerAuth: [] }],
};

const options = {
  definition,
  apis: [
    path.join(__dirname, '../../modules/**/*.routes.js'),
  ],
};

export const swaggerSpec = swaggerJsdoc(options);

export const setupSwagger = (app) => {
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    customSiteTitle: 'Financial Backend API Docs',
    customCss: '.swagger-ui .topbar { background-color: #1a1a2e; }',
  }));

  // Raw spec endpoint for tooling
  app.get('/docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });
};
