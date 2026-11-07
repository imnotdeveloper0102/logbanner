const { z } = require('zod');

const emailField = z.string().email('Email is not valid').max(254);
const passwordField = z.string().min(8, 'Password must be at least 8 characters').max(128);

const registerSchema = z.object({
  email: emailField,
  password: passwordField,
});

const loginSchema = z.object({
  email: emailField,
  password: z.string().min(1, 'Password is required').max(128),
});

const roleSchema = z.object({
  role: z.enum(['admin', 'viewer']),
});

const pageSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

const eventsQuerySchema = pageSchema.extend({
  rule: z.string().min(1).max(100).optional(),
  ip: z.string().min(1).max(45).optional(),
  severity: z.enum(['info', 'warning', 'critical']).optional(),
  since: z.string().datetime({ offset: true }).optional(),
});

const bansQuerySchema = pageSchema.extend({
  include_revoked: z.enum(['true', 'false']).default('false'),
});

const manualBanSchema = z.object({
  ip: z.string().min(1).max(45),
  reason: z.string().min(1, 'Reason is required').max(500),
  duration_seconds: z.number().int().positive().nullable().default(null),
  rule_id: z.string().uuid().optional(),
});

// Rule edit (stage 6). Every field is optional, but at least one
// must be present; `enabled` is edited through the same PATCH, so
// there is a single endpoint and a single audit trail for a rule
// change. Pattern syntax is checked in the route with a real
// regex compile attempt, which zod alone cannot do.
const rulePatchSchema = z
  .object({
    threshold: z.number().int().positive().optional(),
    window_seconds: z.number().int().positive().optional(),
    ban_seconds: z.number().int().positive().optional(),
    action: z.enum(['ban', 'log']).optional(),
    enabled: z.boolean().optional(),
    pattern: z.string().min(1).max(2000).optional(),
    escalation: z.array(z.number().int().positive().nullable()).max(20).optional(),
  })
  .refine((body) => Object.keys(body).length > 0, {
    message: 'At least one field must be provided',
  });

const listCreateSchema = z.object({
  kind: z.enum(['whitelist', 'blacklist']),
  value: z.string().min(1).max(45),
  reason: z.string().max(500).default(''),
});

module.exports = {
  registerSchema,
  loginSchema,
  roleSchema,
  eventsQuerySchema,
  bansQuerySchema,
  manualBanSchema,
  rulePatchSchema,
  listCreateSchema,
  pageSchema,
};
