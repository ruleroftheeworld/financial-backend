import { policies } from './policies.js';

/**
 * Evaluates whether a user can perform an action on a resource given policies and context.
 */
export const evaluatePolicy = ({ user, action, resource, resourceData, context }) => {
  // Normalize roles
  const userRolesRaw = Array.isArray(user.roles) ? user.roles : [user.role];
  const userRoles = userRolesRaw.map(r => r?.toUpperCase()).filter(Boolean);

  // Default deny
  let isAllowed = false;

  for (const policy of policies) {
    // 1. Role match
    const roleMatch = policy.roles.some(
      r => r === '*' || userRoles.includes(r.toUpperCase())
    );
    if (!roleMatch) continue;

    // 2. Action match
    const actionMatch = policy.actions.some(
      a => a === '*' || a.toLowerCase() === action.toLowerCase()
    );
    if (!actionMatch) continue;

    // 3. Resource match
    const resourceMatch = policy.resources.some(
      res => res === '*' || res.toLowerCase() === resource.toLowerCase()
    );
    if (!resourceMatch) continue;

    // 4. Condition match
    if (policy.condition) {
      if (!policy.condition({ user, resource: resourceData, context })) {
        continue;
      }
    }

    // Match found!
    isAllowed = true;
    break;
  }

  return isAllowed;
};
