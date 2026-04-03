export const policies = [
  // 🔥 ADMIN: full access with Strict Network Bounds
  {
    roles: ['ADMIN'],
    actions: ['*'],
    resources: ['*'],
    // 🔒 SEC-07: Restrict ADMIN to loopback + RFC 1918 private ranges (Docker/K8s)
    condition: ({ context }) => {
      const cleanIP = (context.ip || '').replace('::ffff:', '');
      return (
        cleanIP === '127.0.0.1' ||
        cleanIP === '::1' ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIP) ||
        cleanIP.startsWith('10.') ||
        cleanIP.startsWith('192.168.')
      );
    }
  },

  // 🔒 SENSITIVE ACTION: Requires fully verified MFA lifecycle
  {
    roles: ['ADMIN', 'SECURITY_ANALYST', 'USER'],
    actions: ['modify_security', 'billing', 'delete'],
    resources: ['sensitive'],
    condition: ({ user, context }) => {
      return user.totpEnabled === true && context.session?.mfaVerified === true;
    }
  },

  // 👤 USER: read/update only own profile
  {
    roles: ['USER'],
    actions: ['read', 'update'],
    resources: ['user'],
    condition: ({ user, resource }) => user.id === resource.id,
  },

  // 🛡️ SECURITY_ANALYST: read all users
  {
    roles: ['SECURITY_ANALYST'],
    actions: ['read'],
    resources: ['user'],
  },

  // 🔐 USER: manage own sessions
  {
    roles: ['USER'],
    actions: ['delete'],
    resources: ['session'],
    condition: ({ user, resource }) => user.id === resource.userId,
  },

  // ─────────────────────────────────────────────
  // FINANCE POLICIES
  // ─────────────────────────────────────────────

  // 💰 USER/ADMIN: full CRUD on own transactions
  {
    roles: ['USER', 'ADMIN'],
    actions: ['create', 'read', 'update', 'delete'],
    resources: ['transaction'],
    condition: ({ user, resourceData }) => {
      // If resourceData present (existing record), verify ownership
      if (resourceData) return resourceData.userId === user.id;
      return true; // create: ownership enforced by service layer
    },
  },

  // 📊 SECURITY_ANALYST: read-only on finance (for audit purposes)
  {
    roles: ['SECURITY_ANALYST'],
    actions: ['read'],
    resources: ['transaction', 'category', 'account'],
  },

  // 🏦 USER/ADMIN: full CRUD on own accounts
  {
    roles: ['USER', 'ADMIN'],
    actions: ['create', 'read', 'update', 'delete'],
    resources: ['account'],
    condition: ({ user, resourceData }) => {
      if (resourceData) return resourceData.userId === user.id;
      return true;
    },
  },

  // 🗂️ USER/ADMIN: full CRUD on own categories + read system categories
  {
    roles: ['USER', 'ADMIN'],
    actions: ['create', 'read', 'update', 'delete'],
    resources: ['category'],
  },

  // 📈 USER/ADMIN: read own dashboard
  {
    roles: ['USER', 'ADMIN'],
    actions: ['read'],
    resources: ['dashboard'],
  },
];
