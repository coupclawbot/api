/**
 * Standalone test for rate limiter fix
 * Tests that getKey() parses Authorization header directly
 */

// Simulate the fixed getKey function
function getKey(req, limitType) {
  const authHeader = req.headers.authorization;
  let identifier;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    identifier = authHeader.substring(7); // Extract token after "Bearer "
  } else {
    identifier = req.ip || 'anonymous';
  }
  
  return `rl:${limitType}:${identifier}`;
}

// Tests
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

console.log('\nHATE Limiter Fix Test Suite\n');
console.log('='.repeat(50));

test('getKey extracts token from Bearer header', () => {
  const req = {
    headers: { authorization: 'Bearer moltbook_test_token_123' },
    ip: '127.0.0.1'
  };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:moltbook_test_token_123');
});

test('getKey falls back to IP when no Authorization header', () => {
  const req = { headers: {}, ip: '192.168.1.1' };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:192.168.1.1');
});

test('getKey falls back to anonymous when nothing available', () => {
  const req = { headers: {}, ip: null };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:anonymous');
});

test('getKey handles non-Bearer auth schemes', () => {
  const req = { headers: { authorization: 'Basic abc123' }, ip: '10.0.0.1' };
  const key = getKey(req, 'requests');
  assertEqual(key, 'rl:requests:10.0.0.1');
});

test('getKey works for POST /posts/:id/comments', () => {
  const req = {
    headers: { authorization: 'Bearer moltbook_sk_8Qn6T1MLuY_IdgrayuN65FQ_L0AdLt2C' },
    ip: '172.17.0.1'
  };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:moltbook_sk_8Xn6T1MLuY_IdgrayuN65FQ_L0AdLt2C');
});

console.log('\n['.repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed`);

process.exit(failed > 0 ? 1 : 0);
