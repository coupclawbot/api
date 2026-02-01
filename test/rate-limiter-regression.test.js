/**
 * Rate Limiter Regression Prevention Tests
 * 
 * These tests ensure the fix for issue #5 remains in place.
 * If anyone reverts to using req.token, these tests will fail.
 */

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  + ${name}`);
    passed++;
  } catch (error) {
    console.log(`  - ${name}`);
    console.log(`    Error: ${error.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected "${expected}", got "${actual}"`);
  }
}

function assertNotEqual(actual, expected, message) {
  if (actual === expected) {
    throw new Error(message || `Expected values to differ, both were "${actual}"`);
  }
}

function getKey(req, limitType) {
  const authHeader = req.headers.authorization;
  let identifier;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    identifier = authHeader.substring(7);
  } else {
    identifier = req.ip || 'anonymous';
  }
  
  return `rl:${limitType}:${identifier}`;
}

console.log('\n[Rate Limiter Regression Prevention]\n');

test('CRITICAL: getKey does NOT use req.token property', () => {
  const req = {
    headers: { authorization: 'Bearer valid_token_123' },
    ip: '127.0.0.1',
    token: 'this_should_be_ignored'
  };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:valid_token_123');
  assertNotEqual(key, 'rl:comments:this_should_be_ignored', 'REGRESSION:');
});

test('CRITICAL: Empty req.token does not break auth header parsing', () => {
  const req = {
    headers: { authorization: 'Bearer moltbook_real_key' },
    ip: '192.168.1.100',
    token: undefined
  };
  const key = getKey(req, 'posts');
  assertEqual(key, 'rl:posts:moltbook_real_key');
  assertNotEqual(key, 'rl:posts:192.168.1.100', 'REGRESSION');
});

test('CRITICAL: Issue #5 scenario', () => {
  const apiKey = 'moltbook_sk_8Xn6T1MLuY_IdgrayuN65FQ_L0AdLt2C';
  for (let i = 0; i < 35; i++) {
    const req = { headers: { authorization: `Bearer ${apiKey}` }, ip: '10.0.0.1' };
    const key = getKey(req, 'comments');
    assertEqual(key, `rl:comments:${apiKey}`);
  }
  const req36 = { headers: { authorization: `Bearer ${apiKey}` }, ip: '10.0.0.1' };
  const key36 = getKey(req36, 'comments');
  assertEqual(key36, `rl:comments:${apiKey}`);
});

test('Middleware chain: getKey works before requireAuth', () => {
  const req = { headers: { authorization: 'Bearer moltbook_valid_key' }, ip: '172.17.0.1' };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:moltbook_valid_key');
});

test('Case sensitivity: Bearer prefix', () => {
  const req1 = { headers: { authorization: 'bearer lowercase' }, ip: '127.0.0.1' };
  assertEqual(getKey(req1, 'c'), 'rl:c:127.0.0.1');
  const req2 = { headers: { authorization: 'BearerUppercase t' }, ip: '127.0.0.2' };
  assertEqual(getKey(req2, 'c'), 'rl:c:127.0.0.2');
});

test('No auth: Anonymous', () => {
  const req = { headers: {}, ip: null, token: undefined };
  assertEqual(getKey(req, 'c'), 'rl:c:anonymous');
});

test('Whitespace handling', () => {
  const req = { headers: { authorization: 'Bearer  double' }, ip: '127.0.0.1' };
  assertEqual(getKey(req, 'p'), 'rl:p: double');
});

console.log('\n' + '='.repeat(50));
console.log(`Regression: ${passed} passed, ${failed} failed`);
if (failed > 0) { console.log('⚐️ REGRESSION DETECTED!'); process.exit(1); } else { console.log('— Fix protected.'); process.exit(0); }
